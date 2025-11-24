#!/bin/bash

DEPS=(gcc make)
for dep in "${DEPS[@]}"; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo -e "\e[31m[ERROR]\e[0m Missing '$dep'"
    MISSING_DEPLOY=1
  fi
done
HEADER_DEPS=(pcre.h zlib.h ssl.h)
for header in "${HEADER_DEPS[@]}"; do
    if ! find /usr/include /usr/local/include -name "$header" -print -quit | grep -q .; then
        echo -e "\e[31m[ERROR]\e[0m Missing '${header/.h/-dev}'"
        MISSING_DEPLOY=1
    fi
done

if [ "$MISSING_DEPLOY" = "1" ]; then
  echo -e "\e[31mPlease install missing packages and retry\e[0m"
  exit 1
fi

if [ -z "$NGINX_VERSION" ]; then
  NGINX_VERSION=$(nginx -v 2>&1 | cut -c 22-)
  if [ -z "$NGINX_VERSION" ]; then
    echo -e "\e[33mPlease set the NGINX_VERSION variable\e[0m";
    exit 2
  fi
  echo "Nginx version: $NGINX_VERSION";
fi

MODULE_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd -- "$MODULE_PATH" || exit

if [ -z ${NGINX_PATH+x} ]; then
  wget "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
  tar -xzf "nginx-${NGINX_VERSION}.tar.gz"
  NGINX_PATH="${MODULE_PATH}/nginx-${NGINX_VERSION}/"
fi

CONFIG_ARGS=$(nginx -V 2>&1 | tail -n 1 | cut -c 21- | sed 's/--add-dynamic-module=.*//g')
CONFIG_ARGS="${CONFIG_ARGS} --add-dynamic-module=${MODULE_PATH}"
echo "$CONFIG_ARGS"

(
  cd "$NGINX_PATH" || exit 3
  bash -c "./configure ${CONFIG_ARGS}"
  make modules -j "$(nproc)"
) || exit 9


mv "${NGINX_PATH}/objs/ngx_http_js_challenge_module.so" "$MODULE_PATH"
rm -r "${NGINX_PATH}"
rm "nginx-${NGINX_VERSION}.tar.gz"

echo ""
echo -e "\e[30;47mDone! Load the dynamic module ${MODULE_PATH}ngx_http_js_challenge_module.so and restart nginx to install\e[0m"
