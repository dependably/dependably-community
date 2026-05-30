window.onload = function () {
  const isManagement = window.location.pathname.indexOf('/api/v1/docs') === 0;
  const specUrl = isManagement ? '/openapi/management.json' : '/openapi/protocol.json';
  document.title = isManagement
    ? 'Dependably Management API'
    : 'Dependably Registry Protocols';
  window.ui = SwaggerUIBundle({
    url: specUrl,
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    plugins: [SwaggerUIBundle.plugins.DownloadUrl],
    layout: 'StandaloneLayout',
  });
};
