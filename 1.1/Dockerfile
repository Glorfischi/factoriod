# vim:set ft=dockerfile:
FROM debian:buster AS build
LABEL stage=build

ENV VERSION=1.1.27 
ENV SHA1=564df2dfd204679af6afa574d612d16b1b388453 

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
		ca-certificates \
    xz-utils \
    && rm -rf /var/lib/apt/lists/* 

RUN curl -sSL "https://www.factorio.com/get-download/$VERSION/headless/linux64" -o "/tmp/factorio_headless_x64_$VERSION.tar.xz" 
RUN tar xf "/tmp/factorio_headless_x64_$VERSION.tar.xz" --directory /opt 

RUN mkdir -p /opt/factorio/config/ \
    && mkdir -p /opt/factorio/saves \
    && chown -R 845:845 /opt/factorio 

    
FROM debian:buster-slim
# Create factorio user and exectue container as this user
RUN groupadd --gid 845 --system factorio \
	&& useradd \
		--gid factorio \
		--home-dir /opt/factorio \
		--no-create-home \
		--system \
		--uid 845 \
		factorio

COPY --from=build /opt /opt
VOLUME ["/opt/factorio/saves"]

USER factorio
WORKDIR /opt/factorio

# Game port
EXPOSE 34197/udp 
# RCON port
EXPOSE 27015/tcp 

ENTRYPOINT ["/opt/factorio/bin/x64/factorio"]
