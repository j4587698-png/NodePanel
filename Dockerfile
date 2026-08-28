# syntax=docker/dockerfile:1

# ---------- Build ----------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
WORKDIR /src/panel/NodePanel.Panel
RUN dotnet restore NodePanel.Panel.csproj
RUN dotnet publish NodePanel.Panel.csproj -c Release -o /app/publish --no-restore

# ---------- Runtime ----------
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

# FreeSql SQLite provider relies on a native sqlite library.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/publish .

# Persist the SQLite database and panel state outside the image layer.
ENV Panel__DataFilePath=/app/data/panel-state.json

# Force the first-run install wizard: blank the shipped SQLite connection so
# the panel is not treated as already configured. The wizard then writes the
# real connection string and admin account into /app/data/panel.settings.json
# (loaded at startup), which survives container restarts.
RUN sed -i 's/"DbType": "sqlite"/"DbType": ""/' /app/appsettings.json \
    && sed -i 's/"DbConnectionString": "Data Source=server.db"/"DbConnectionString": ""/' /app/appsettings.json

VOLUME ["/app/data"]
EXPOSE 80 443

ENTRYPOINT ["dotnet", "NodePanel.Panel.dll"]
