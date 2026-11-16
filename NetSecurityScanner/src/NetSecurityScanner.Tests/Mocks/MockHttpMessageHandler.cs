using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Tests.Mocks
{
  public class MockHttpMessageHandler : HttpMessageHandler
  {
    private readonly HttpStatusCode _statusCode;
    private readonly string _responseContent;

    public MockHttpMessageHandler(HttpStatusCode statusCode, string responseContent)
    {
      _statusCode = statusCode;
      _responseContent = responseContent;
    }

    public string? LastRequestUri { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
      LastRequestUri = request.RequestUri?.ToString();
      var response = new HttpResponseMessage(_statusCode)
      {
        Content = new StringContent(_responseContent)
      };
      return Task.FromResult(response);
    }
  }
}