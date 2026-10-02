{
  frontend = {
    uid = 1001;
    subordinateIdStart = 165536;

    gitlab = {
      url = "https://gitlab.example";
      healthUrl = "https://gitlab.example/users/sign_in";
      caCertificate = null;
    };

    runner = {
      name = "A-frontend-podman";
      cpus = "2";
      memory = "4g";
      shmSizeBytes = 1073741824;
      defaultJobImage = "docker.io/library/node:22.22.0-bookworm";
      allowedImages = [
        "docker.io/library/node:*"
        "mcr.microsoft.com/playwright:*"
        "docker.io/curlimages/curl:*"
      ];
      allowedServices = [ ];
    };

    network = {
      requiredInterface = "tailscale0";
      dns = "100.100.100.100";
    };

  };

  dotnet = {
    uid = 1002;
    subordinateIdStart = 231072;

    gitlab = {
      url = "https://gitlab.example";
      healthUrl = "https://gitlab.example/users/sign_in";
      caCertificate = null;
    };

    runner = {
      name = "A-dotnet-podman";
      cpus = "4";
      memory = "6g";
      shmSizeBytes = 1073741824;
      defaultJobImage = "mcr.microsoft.com/dotnet/sdk:10.0.302-noble";
      allowedImages = [
        "mcr.microsoft.com/dotnet/sdk:*"
        "mcr.microsoft.com/dotnet/runtime:*"
        "mcr.microsoft.com/dotnet/aspnet:*"
      ];
      allowedServices = [ "mcr.microsoft.com/mssql/server:*" ];
    };

    network = {
      requiredInterface = "tailscale0";
      dns = "100.100.100.100";
    };

  };
}
