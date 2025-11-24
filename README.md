# ngx_http_js_challenge_module

[![GitHub License](https://img.shields.io/github/license/bugsoff/ngx_http_js_challenge_module.svg)](LICENSE)
[![CodeFactor](https://www.codefactor.io/repository/github/bugsoff/ngx_http_js_challenge_module/badge)](https://www.codefactor.io/repository/github/bugsoff/ngx_http_js_challenge_module)

Simple JavaScript proof-of-work based access control for Nginx, designed to provide security with minimal overhead.

## Features

- **Lightweight Integration:** Easy to integrate with existing Nginx installations.
- **Configurable Security:** Flexible settings to adjust security strength and client experience.
- **Minimal Performance Impact:** Designed to operate with virtually no additional server load.

## Quick Start

1. **Installation**
   Add the following line to your `nginx.conf`:
   ```
   load_module /path/to/ngx_http_js_challenge_module.so;
   ```

2. **Configuration**
   For basic setup, update your server block as follows:

   ```
   server {
       js_challenge on;
       js_challenge_secret "changeme!";  # Ensure to replace this with a strong secret in production
   }
   ```

## Installation

To install the ngx_http_js_challenge_module, follow these steps:

1. Add the module loading directive to your Nginx configuration file (`/etc/nginx/nginx.conf`) at root section:
   ```
   load_module /path/to/ngx_http_js_challenge_module.so;
   ```

2. Apply the changes by reloading Nginx:
   ```
   nginx -s reload
   ```

## Configuration

### Advanced Configuration

For more complex setups, including exemptions for specific paths:

```nginx configuration
server {
    js_challenge on;
    js_challenge_secret "changeme!";
    js_challenge_html "/path/to/body.html";
    js_challenge_bucket_duration 3600;
    js_challenge_title "Verifying your browser...";

    location /static {
        js_challenge off;
        alias /static_files/;
    }

    location /sensitive {
        js_challenge_bucket_duration 600;
        # Add further customization here
    }
    
}
```

### Dynamic configuration

To enable or disable the module depending on external request conditions:
```nginx configuration
 geo $whitelisted_addr {
     127.0.0.1       off;
     192.168.0.0/24  off;
     default         on;
 }
 
 map $http_user_agent $whitelisted_agent {
     "~*Googlebot"   off;
     default         on;
 }
 
 map "$whitelisted_addr:$whitelisted_agent" $js_challenge_enabled {
     "~*off"         off;
     default         on;
 }
 
 server {
    js_challenge $js_challenge_enabled;
    js_challenge_secret "changeme!";
 
    location /static {
        js_challenge off;
    }
}
    
```


### Parameters

- **js_challenge on|off** Toggle javascript challenges for this config block
- **js_challenge_secret "secret"** Secret for generating the challenges. DEFAULT: "changeme"
- **js_challenge_html "/path/to/file.html"** Path to html file to be inserted in the `<body>` tag of the interstitial page
- **js_challenge_title "title"** Will be inserted in the `<title>` tag of the interstitial page. DEFAULT: "Verifying your browser..."
- **js_challenge_bucket_duration time** Interval to prompt js challenge, in seconds. DEFAULT: 3600


## Build from source

These steps have to be performed on machine with compatible configuration (same nginx, glibc, openssl version etc.)

1. Install dependencies
    ```
      apt update
      apt install build-essential libpcre3-dev zlib1g-dev libssl-dev -y
    ```
2. Compile the module
    ```
    git clone https://github.com/bugsoff/ngx_http_js_challenge_module
    bash ngx_http_js_challenge_module/build.sh
    ```
3. The dynamic module can be found at `ngx_http_js_challenge_module/ngx_http_js_challenge_module.so`

### Docker

Here is an example Dockerfile for installing the module into an Nginx container:

```dockerfile
FROM nginx:1.29.3-alpine

RUN apk add --no-cache git bash linux-headers build-base pcre-dev openssl-dev zlib-dev

RUN git clone https://github.com/bugsoff/ngx_http_js_challenge_module.git &&\
    ngx_http_js_challenge_module/build.sh &&\
    mv ngx_http_js_challenge_module/ngx_http_js_challenge_module.so /etc/nginx/modules &&\
    rm -rf ./ngx_http_js_challenge_module

RUN TMP_FILE="$(mktemp)" &&\
    echo "load_module modules/ngx_http_js_challenge_module.so;" > "$TMP_FILE" &&\
    cat "/etc/nginx/nginx.conf" >> "$TMP_FILE" &&\
    mv "$TMP_FILE" "/etc/nginx/nginx.conf"
```

### Throughput
<p align="center">
  <img width="600px" src="throughput.png"/>
</p>
