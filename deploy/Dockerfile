FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG VERSION=0.0.0-dev
WORKDIR /src
COPY S1Wazuh.Collector/ S1Wazuh.Collector/
RUN dotnet publish S1Wazuh.Collector -c Release -p:Version=${VERSION} -o /out

FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app
COPY --from=build /out .
# Output (NDJSON for Wazuh) and checkpoint state. Mount both as volumes.
VOLUME ["/var/ossec/logs/sentinelone", "/var/lib/s1wazuh"]
# Required at runtime: SentinelOne__BaseUrl and SentinelOne__ApiToken (env vars).
ENTRYPOINT ["dotnet", "s1wazuh.dll"]
