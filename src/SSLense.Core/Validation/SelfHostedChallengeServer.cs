using System.Collections.Concurrent;
using System.Net;
using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.Errors;

namespace SSLense.Core.Validation;

/// <summary>
/// Answers HTTP-01 challenges itself, through HTTP.sys on port 80, so a site needs no HTTP binding of its own
/// (docs/design/self-hosted-http-validation.md). HTTP.sys gives a strong wildcard registration such as
/// <c>http://+:80/.well-known/acme-challenge/</c> precedence over the host names IIS registers, so IIS keeps serving
/// everything else while SSLense answers the challenge path, and only while a validation runs.
/// </summary>
public interface ISelfHostedChallengeServer
{
    /// <summary>Serves the challenge's key authorization until the result is disposed.</summary>
    Task<IAsyncDisposable> ServeAsync(AcmeHttpChallenge challenge, CancellationToken cancellationToken);

    /// <summary>Null when port 80 can be used, or why it cannot.</summary>
    string? CheckAvailable();
}

internal sealed class SelfHostedChallengeServer : ISelfHostedChallengeServer, IDisposable
{
    public const string Prefix = "http://+:80/.well-known/acme-challenge/";

    private readonly ConcurrentDictionary<string, string> _tokens = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();
    private readonly string _prefix;
    private HttpListener? _listener;

    public SelfHostedChallengeServer() : this(Prefix)
    {
    }

    /// <param name="prefix">Another prefix, such as a free port on localhost, for tests.</param>
    internal SelfHostedChallengeServer(string prefix) => _prefix = prefix;

    public Task<IAsyncDisposable> ServeAsync(AcmeHttpChallenge challenge, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            _tokens[challenge.Token] = challenge.KeyAuthorization;
            try
            {
                StartIfStopped();
            }
            catch
            {
                _tokens.TryRemove(challenge.Token, out _);
                throw;
            }
        }

        return Task.FromResult<IAsyncDisposable>(new Release(this, challenge.Token));
    }

    public string? CheckAvailable()
    {
        lock (_gate)
        {
            if (_listener is not null)
            {
                return null;
            }

            try
            {
                StartIfStopped();
                return null;
            }
            catch (SslenseException exception)
            {
                return exception.Message;
            }
            finally
            {
                if (_tokens.IsEmpty)
                {
                    Stop();
                }
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            Stop();
        }
    }

    private void StartIfStopped()
    {
        if (_listener is not null)
        {
            return;
        }

        var listener = new HttpListener();
        listener.Prefixes.Add(_prefix);
        try
        {
            listener.Start();
        }
        catch (HttpListenerException exception)
        {
            listener.Close();
            throw new SslenseException(ErrorCodes.SelfHostedPortUnavailable,
                $"SSLense could not answer on port 80 itself: {exception.Message} (error {exception.ErrorCode}). Another program may hold port 80 " +
                "outside HTTP.sys, or SSLense is not running as Administrator.",
                exception);
        }

        _listener = listener;
        _ = Task.Run(() => AnswerAsync(listener));
    }

    private void Stop()
    {
        var listener = _listener;
        _listener = null;
        if (listener is null)
        {
            return;
        }

        try
        {
            listener.Stop();
        }
        finally
        {
            listener.Close();
        }
    }

    private async Task AnswerAsync(HttpListener listener)
    {
        while (listener.IsListening)
        {
            HttpListenerContext context;
            try
            {
                context = await listener.GetContextAsync().ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is HttpListenerException or ObjectDisposedException or InvalidOperationException)
            {
                return;
            }

            try
            {
                var token = context.Request.Url?.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? string.Empty;
                if (context.Request.HttpMethod is "GET" or "HEAD" && _tokens.TryGetValue(token, out var keyAuthorization))
                {
                    var body = Encoding.ASCII.GetBytes(keyAuthorization);
                    context.Response.StatusCode = 200;
                    context.Response.ContentType = "text/plain";
                    context.Response.ContentLength64 = body.Length;
                    if (context.Request.HttpMethod == "GET")
                    {
                        await context.Response.OutputStream.WriteAsync(body).ConfigureAwait(false);
                    }
                }
                else
                {
                    context.Response.StatusCode = 404;
                }
            }
            catch (Exception exception) when (exception is HttpListenerException or IOException or ObjectDisposedException)
            {
                // The client went away; the next request is answered as usual.
            }
            finally
            {
                try { context.Response.Close(); }
                catch (Exception exception) when (exception is HttpListenerException or ObjectDisposedException) { }
            }
        }
    }

    private void Remove(string token)
    {
        lock (_gate)
        {
            _tokens.TryRemove(token, out _);
            if (_tokens.IsEmpty)
            {
                Stop();
            }
        }
    }

    private sealed class Release(SelfHostedChallengeServer server, string token) : IAsyncDisposable
    {
        private int _released;

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                server.Remove(token);
            }

            return ValueTask.CompletedTask;
        }
    }
}
