FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build

ARG BUILD_CONFIGURATION=Release
WORKDIR /src

COPY ["Fakebook.UploadServer.csproj", "."]
RUN dotnet restore "Fakebook.UploadServer.csproj"

COPY . .
RUN dotnet publish "Fakebook.UploadServer.csproj" \
    --configuration "$BUILD_CONFIGURATION" \
    --output /app/publish \
    --no-restore \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS final

WORKDIR /app

# Docker Compose probes /health/ready from inside the container.
RUN apk add --no-cache curl

ENV ASPNETCORE_HTTP_PORTS=4001
EXPOSE 4001

COPY --from=build /app/publish .

# The mounted media volume must remain writable after dropping root privileges.
RUN mkdir -p /data/media \
    && chown -R $APP_UID:$APP_UID /data/media

USER $APP_UID
ENTRYPOINT ["dotnet", "Fakebook.UploadServer.dll"]
