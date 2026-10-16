{
  # Add own tailscale key and mv variables/template.credentials.nix to variables/credentials.nix
  tailscale = {
    authKey = "";
  };

  authentik = {
    clientId = "VJG2UyUygcx7qNUQqwiSiMd11C9K1zXLC3G5ohzq";
    clientSecret = "UUYxAr0VQ23cM64u6e8JrVIuj2K6lK35nGOK63kLqcTtdGR3a2JnSU1Artdv8arWootplV2yfCcxFglM0MV5GYOhOCm8FtU94Otu9a8xMLrAJKzZSabopQli2O3Avgaw";
    secretKey = "testzero-authentik-secret-key";
    postgresql = {
      name = "authentik";
      user = "authentik";
      password = "authentik";
    };
    bootstrapPassword = "admin";
    bootstrapEmail = "admin@testzero.local";
    bootstrapToken = "testzero-bootstrap-token";
  };

  grafana = {
    adminUser = "admin";
    adminPassword = "admin";
    secretKey = "testzero-dashboard-secret-key-change-me";
  };

  ssh = {
    rootPassword = "pass";
    userPassword = "pass";
  };

  mtls = {
    caPassword = "testzero-stepca-intermediate-password";
    provisionerPassword = "testzero-stepca-provisioner-password";
  };

  opa = {
    token = "testzero-opa-bearer-token";
  };
}
