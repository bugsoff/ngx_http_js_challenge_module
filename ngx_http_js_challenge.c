#include <ngx_http.h>
#include <ngx_sha1.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>

#define DEFAULT_SECRET "changeme!"
#define SHA1_MD_LEN 20
#define SHA1_STR_LEN 40

#define JS_SOLVER_TEMPLATE \
        "<!DOCTYPE html>" \
        "<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>" \
        "<title>%s</title>" \
        "</head><body>" \
        "<script>" \
        "window.onload=function(){const cE2=()=>{try{const a='_cookie_'+Date['now'](),b=true;document['cookie']=a+'='+b+'; path=/';const c=document['cookie']['split']('; '),d=c['some'](f=>f['startsWith'](a+'='));return(document['cookie']=a+'=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'),d}catch(f){return![];}};if(!cE2()){if(!window.location.search.includes('no_cookie=true')){window.location.search+=(window.location.search?'&':'?')+'no_cookie=true';}else{document.body.innerHTML='<h1>Cookies are required to access this content.</h1><p>Please enable cookies in your browser settings and try again.</p>';}}else{" \
        "!function(){function t(t){t?(f[0]=f[16]=f[1]=f[2]=f[3]=f[4]=f[5]=f[6]=f[7]=f[8]=f[9]=f[10]=f[11]=f[12]=f[13]=f[14]=f[15]=0,this.blocks=f):this.blocks=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],this.h0=1732584193,this.h1=4023233417,this.h2=2562383102,this.h3=271733878,this.h4=3285377520,this.block=this.start=this.bytes=this.hBytes=0,this.finalized=this.hashed=!1,this.first=!0}var h=\"object\"==typeof window?window:{},s=!h.JS_SHA1_NO_NODE_JS&&\"object\"==typeof process&&process.versions&&process.versions.node;s&&(h=global);var i=!h.JS_SHA1_NO_COMMON_JS&&\"object\"==typeof module&&module.exports,e=\"function\"==typeof define&&define.amd,r=\"0123456789abcdef\".split(\"\"),o=[-2147483648,8388608,32768,128],n=[24,16,8,0],a=[\"hex\",\"array\",\"digest\",\"arrayBuffer\"],f=[],u=function(h){return function(s){return new t(!0).update(s)[h]()}},c=function(){var h=u(\"hex\");s&&(h=p(h)),h.create=function(){return new t},h.update=function(t){return h.create().update(t)};for(var i=0;i<a.length;++i){var e=a[i];h[e]=u(e)}return h},p=function(t){var h=eval(\"require('crypto')\"),s=eval(\"require('buffer').Buffer\"),i=function(i){if(\"string\"==typeof i)return h.createHash(\"s1\").update(i,\"utf8\").digest(\"hex\");if(i.constructor===ArrayBuffer)i=new Uint8Array(i);else if(void 0===i.length)return t(i);return h.createHash(\"s1\").update(new s(i)).digest(\"hex\")};return i};t.prototype.update=function(t){if(!this.finalized){var s=\"string\"!=typeof t;s&&t.constructor===h.ArrayBuffer&&(t=new Uint8Array(t));for(var i,e,r=0,o=t.length||0,a=this.blocks;r<o;){if(this.hashed&&(this.hashed=!1,a[0]=this.block,a[16]=a[1]=a[2]=a[3]=a[4]=a[5]=a[6]=a[7]=a[8]=a[9]=a[10]=a[11]=a[12]=a[13]=a[14]=a[15]=0),s)for(e=this.start;r<o&&e<64;++r)a[e>>2]|=t[r]<<n[3&e++];else for(e=this.start;r<o&&e<64;++r)(i=t.charCodeAt(r))<128?a[e>>2]|=i<<n[3&e++]:i<2048?(a[e>>2]|=(192|i>>6)<<n[3&e++],a[e>>2]|=(128|63&i)<<n[3&e++]):i<55296||i>=57344?(a[e>>2]|=(224|i>>12)<<n[3&e++],a[e>>2]|=(128|i>>6&63)<<n[3&e++],a[e>>2]|=(128|63&i)<<n[3&e++]):(i=65536+((1023&i)<<10|1023&t.charCodeAt(++r)),a[e>>2]|=(240|i>>18)<<n[3&e++],a[e>>2]|=(128|i>>12&63)<<n[3&e++],a[e>>2]|=(128|i>>6&63)<<n[3&e++],a[e>>2]|=(128|63&i)<<n[3&e++]);this.lastByteIndex=e,this.bytes+=e-this.start,e>=64?(this.block=a[16],this.start=e-64,this.hash(),this.hashed=!0):this.start=e}return this.bytes>4294967295&&(this.hBytes+=this.bytes/4294967296<<0,this.bytes=this.bytes%%4294967296),this}},t.prototype.finalize=function(){if(!this.finalized){this.finalized=!0;var t=this.blocks,h=this.lastByteIndex;t[16]=this.block,t[h>>2]|=o[3&h],this.block=t[16],h>=56&&(this.hashed||this.hash(),t[0]=this.block,t[16]=t[1]=t[2]=t[3]=t[4]=t[5]=t[6]=t[7]=t[8]=t[9]=t[10]=t[11]=t[12]=t[13]=t[14]=t[15]=0),t[14]=this.hBytes<<3|this.bytes>>>29,t[15]=this.bytes<<3,this.hash()}},t.prototype.hash=function(){var t,h,s=this.h0,i=this.h1,e=this.h2,r=this.h3,o=this.h4,n=this.blocks;for(t=16;t<80;++t)h=n[t-3]^n[t-8]^n[t-14]^n[t-16],n[t]=h<<1|h>>>31;for(t=0;t<20;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i&e|~i&r)+o+1518500249+n[t]<<0)<<5|o>>>27)+(s&(i=i<<30|i>>>2)|~s&e)+r+1518500249+n[t+1]<<0)<<5|r>>>27)+(o&(s=s<<30|s>>>2)|~o&i)+e+1518500249+n[t+2]<<0)<<5|e>>>27)+(r&(o=o<<30|o>>>2)|~r&s)+i+1518500249+n[t+3]<<0)<<5|i>>>27)+(e&(r=r<<30|r>>>2)|~e&o)+s+1518500249+n[t+4]<<0,e=e<<30|e>>>2;for(;t<40;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i^e^r)+o+1859775393+n[t]<<0)<<5|o>>>27)+(s^(i=i<<30|i>>>2)^e)+r+1859775393+n[t+1]<<0)<<5|r>>>27)+(o^(s=s<<30|s>>>2)^i)+e+1859775393+n[t+2]<<0)<<5|e>>>27)+(r^(o=o<<30|o>>>2)^s)+i+1859775393+n[t+3]<<0)<<5|i>>>27)+(e^(r=r<<30|r>>>2)^o)+s+1859775393+n[t+4]<<0,e=e<<30|e>>>2;for(;t<60;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i&e|i&r|e&r)+o-1894007588+n[t]<<0)<<5|o>>>27)+(s&(i=i<<30|i>>>2)|s&e|i&e)+r-1894007588+n[t+1]<<0)<<5|r>>>27)+(o&(s=s<<30|s>>>2)|o&i|s&i)+e-1894007588+n[t+2]<<0)<<5|e>>>27)+(r&(o=o<<30|o>>>2)|r&s|o&s)+i-1894007588+n[t+3]<<0)<<5|i>>>27)+(e&(r=r<<30|r>>>2)|e&o|r&o)+s-1894007588+n[t+4]<<0,e=e<<30|e>>>2;for(;t<80;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i^e^r)+o-899497514+n[t]<<0)<<5|o>>>27)+(s^(i=i<<30|i>>>2)^e)+r-899497514+n[t+1]<<0)<<5|r>>>27)+(o^(s=s<<30|s>>>2)^i)+e-899497514+n[t+2]<<0)<<5|e>>>27)+(r^(o=o<<30|o>>>2)^s)+i-899497514+n[t+3]<<0)<<5|i>>>27)+(e^(r=r<<30|r>>>2)^o)+s-899497514+n[t+4]<<0,e=e<<30|e>>>2;this.h0=this.h0+s<<0,this.h1=this.h1+i<<0,this.h2=this.h2+e<<0,this.h3=this.h3+r<<0,this.h4=this.h4+o<<0},t.prototype.hex=function(){this.finalize();var t=this.h0,h=this.h1,s=this.h2,i=this.h3,e=this.h4;return r[t>>28&15]+r[t>>24&15]+r[t>>20&15]+r[t>>16&15]+r[t>>12&15]+r[t>>8&15]+r[t>>4&15]+r[15&t]+r[h>>28&15]+r[h>>24&15]+r[h>>20&15]+r[h>>16&15]+r[h>>12&15]+r[h>>8&15]+r[h>>4&15]+r[15&h]+r[s>>28&15]+r[s>>24&15]+r[s>>20&15]+r[s>>16&15]+r[s>>12&15]+r[s>>8&15]+r[s>>4&15]+r[15&s]+r[i>>28&15]+r[i>>24&15]+r[i>>20&15]+r[i>>16&15]+r[i>>12&15]+r[i>>8&15]+r[i>>4&15]+r[15&i]+r[e>>28&15]+r[e>>24&15]+r[e>>20&15]+r[e>>16&15]+r[e>>12&15]+r[e>>8&15]+r[e>>4&15]+r[15&e]},t.prototype.toString=t.prototype.hex,t.prototype.digest=function(){this.finalize();var t=this.h0,h=this.h1,s=this.h2,i=this.h3,e=this.h4;return[t>>24&255,t>>16&255,t>>8&255,255&t,h>>24&255,h>>16&255,h>>8&255,255&h,s>>24&255,s>>16&255,s>>8&255,255&s,i>>24&255,i>>16&255,i>>8&255,255&i,e>>24&255,e>>16&255,e>>8&255,255&e]},t.prototype.array=t.prototype.digest,t.prototype.arrayBuffer=function(){this.finalize();var t=new ArrayBuffer(20),h=new DataView(t);return h.setUint32(0,this.h0),h.setUint32(4,this.h1),h.setUint32(8,this.h2),h.setUint32(12,this.h3),h.setUint32(16,this.h4),t};var y=c();i?module.exports=y:(h.s1=y,e&&define(function(){return y}))}();" \
        "const a0_0x2a54=['%s','c_token=','array'];(function(_0x41abf3,_0x2a548e){const _0x4457dc=function(_0x804ad2){while(--_0x804ad2){_0x41abf3['push'](_0x41abf3['shift']());}};_0x4457dc(++_0x2a548e);}(a0_0x2a54,0x178));const a0_0x4457=function(_0x41abf3,_0x2a548e){_0x41abf3=_0x41abf3-0x0;let _0x4457dc=a0_0x2a54[_0x41abf3];return _0x4457dc;};let c=a0_0x4457('0x2');let i=0x0;let n1=parseInt('0x'+c[0x0]);while(!![]){let s=s1[a0_0x4457('0x1')](c+i);if(s[n1]===0xb0&&s[n1+0x1]===0xb&&(!(s[+[]]|0)||!(s[+[]]-1))){document['cookie']=a0_0x4457('0x0')+c+i+'; path=/';window.location.reload();break;}i++;};" \
        ";window.setTimeout(function(){window.location.reload()}, 10000)}}" \
        "</script>" \
        "%s" \
        "</body></html>"

#define DEFAULT_TITLE "Browser Verification"

typedef struct {
    ngx_flag_t enabled;
    ngx_uint_t bucket_duration;
    ngx_str_t secret;
    ngx_str_t html_path;
    ngx_str_t title;
    char *html;
    ngx_str_t enabled_variable_name;
    ngx_flag_t challenge_served;
} ngx_http_js_challenge_loc_conf_t;

static ngx_int_t ngx_http_js_challenge(ngx_conf_t *cf);
static char *ngx_http_js_challenge_set_flag_or_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_js_challenge_served_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_js_challenge_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_js_challenge_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_js_challenge_handler(ngx_http_request_t *r);

static void buf2hex(const unsigned char *buf, size_t buflen, char *hex_string);
static unsigned char *__sha1(const unsigned char *d, size_t n, unsigned char *md);
static int is_private_ip(const char *ip);
static int get_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value);


static ngx_command_t ngx_http_js_challenge_commands[] = {
        {
                ngx_string("js_challenge"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_SIF_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_http_js_challenge_set_flag_or_variable,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_js_challenge_loc_conf_t, enabled),  // Use for "on"/"off"
                NULL
        },
        {
                ngx_string("js_challenge_bucket_duration"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_num_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_js_challenge_loc_conf_t, bucket_duration),
                NULL
        },
        {
                ngx_string("js_challenge_secret"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_js_challenge_loc_conf_t, secret),
                NULL
        },
        {
                ngx_string("js_challenge_html"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_js_challenge_loc_conf_t, html_path),
                NULL
        },
        {
                ngx_string("js_challenge_title"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_js_challenge_loc_conf_t, title),
                NULL
        },
        ngx_null_command
};

static ngx_http_variable_t ngx_http_js_challenge_vars[] = {
        {
                ngx_string("js_challenge_served"),
                NULL,
                ngx_http_js_challenge_served_var,
                0,
                NGX_HTTP_VAR_CHANGEABLE,
                0
        },
        ngx_http_null_variable
};

/*
 * Module context
 */
static ngx_http_module_t ngx_http_js_challenge_module_ctx = {
        NULL,                   // preconfiguration
        ngx_http_js_challenge,  // postconfiguration

        NULL,
        NULL,

        NULL,
        NULL,

        ngx_http_js_challenge_create_loc_conf,
        ngx_http_js_challenge_merge_loc_conf
};

ngx_module_t ngx_http_js_challenge_module = {
        NGX_MODULE_V1,
        &ngx_http_js_challenge_module_ctx,
        ngx_http_js_challenge_commands,
        NGX_HTTP_MODULE,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NGX_MODULE_V1_PADDING
};


static void *ngx_http_js_challenge_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_js_challenge_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_js_challenge_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->secret = (ngx_str_t) {0, NULL};
    conf->bucket_duration = NGX_CONF_UNSET_UINT;
    conf->enabled = NGX_CONF_UNSET;
    conf->enabled_variable_name = (ngx_str_t) {0, NULL};
    conf->challenge_served = 0;

    return conf;
}


static char *ngx_http_js_challenge_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_js_challenge_loc_conf_t *prev = parent;
    ngx_http_js_challenge_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->bucket_duration, prev->bucket_duration, 3600)
    ngx_conf_merge_value(conf->enabled, prev->enabled, 0)
    ngx_conf_merge_str_value(conf->enabled_variable_name, prev->enabled_variable_name, NULL)
    ngx_conf_merge_str_value(conf->secret, prev->secret, DEFAULT_SECRET)
    ngx_conf_merge_str_value(conf->html_path, prev->html_path, NULL)
    ngx_conf_merge_str_value(conf->title, prev->title, DEFAULT_TITLE)

    if (conf->enabled != 1 && conf->enabled_variable_name.data != NULL && conf->enabled_variable_name.len > 0) {
        conf->enabled = NGX_CONF_UNSET;
    } else if (conf->enabled == NGX_CONF_UNSET) {
        conf->enabled = 0;
    }

    if (conf->bucket_duration < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[js-challenge] bucket_duration must be equal or more than 1");
        return NGX_CONF_ERROR;
    }

    if (conf->html_path.data == NULL) {
        conf->html = NULL;
    } else if (conf->enabled || conf->enabled_variable_name.len > 0) {

        // Read file in memory
        char path[PATH_MAX];
        memcpy(path, conf->html_path.data, conf->html_path.len);
        *(path + conf->html_path.len) = '\0';

        struct stat info;
        stat(path, &info);

        int fd = open(path, O_RDONLY, 0);
        if (fd < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[js-challenge] html: Could not open file '%s': %s", path, strerror(errno));
            close(fd);
            return NGX_CONF_ERROR;
        }

        conf->html = ngx_palloc(cf->pool, info.st_size);
        int ret = read(fd, conf->html, info.st_size-1);
        *(conf->html+ret) = '\0';
        close(fd);
        if (ret < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[js-challenge] html: Could not read file '%s': %s", path, strerror(errno));
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *ngx_http_js_challenge_set_flag_or_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_js_challenge_loc_conf_t *js_conf = conf;
    ngx_str_t *value = cf->args->elts;

    // Check if the value is "on" or "off" (hardcoded flag)
    if (ngx_strcmp(value[1].data, "on") == 0) {
        js_conf->enabled = 1;
    } else if (ngx_strcmp(value[1].data, "off") == 0) {
        js_conf->enabled = 0;
    } else {
        // If the value starts with '$', treat it as a variable
        if (value[1].data[0] == '$') {
            js_conf->enabled_variable_name.data = value[1].data + 1;
            js_conf->enabled_variable_name.len = value[1].len - 1;
            js_conf->enabled = NGX_CONF_UNSET;  // Variable overrides the flag
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "[js-challenge] invalid value \"%V\" in js_challenge directive, must be \"on\", \"off\", or a variable", &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

////////////////////////////////////////////////////////////////////////////////

/**
 * Challenge = hex( SHA1( concat(bucket, addr, user_agent, secret) ) )
 *
 * @param out 40 bytes long string!
 */
ngx_inline static void get_challenge_string(int32_t bucket, ngx_str_t addr, ngx_str_t user_agent, ngx_str_t secret, char *out) {
    char buf[4096];
    unsigned char md[SHA1_MD_LEN];
    char *p = (char *) &bucket;

    int offset = 0;
    memcpy(buf + offset, p, sizeof(bucket));                // Copy the bucket
    offset += sizeof(int32_t);
    memcpy(buf + offset, addr.data, addr.len);              // Copy the IP address
    offset += addr.len;
    memcpy(buf + offset, user_agent.data, user_agent.len);  // Copy the User-Agent
    offset += user_agent.len;
    memcpy(buf + offset, secret.data, secret.len);          // Copy the secret

    __sha1((unsigned char *) buf, (size_t) (offset + secret.len), md);      // Calculate SHA1 hash of the concatenated data
    buf2hex(md, SHA1_MD_LEN, out);                                          // Convert the hash to a hexadecimal string
}


static int serve_challenge(ngx_http_request_t *r, const char *challenge, const char *html, ngx_str_t title) {
    ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    ngx_chain_t out;

    char challenge_c_str[SHA1_STR_LEN + 1];
    memcpy(challenge_c_str, challenge, SHA1_STR_LEN);
    *(challenge_c_str + SHA1_STR_LEN) = '\0';

    char title_c_str[4096];
    memcpy(title_c_str, title.data, title.len);
    *(title_c_str + title.len) = '\0';

    unsigned char buf[32768];
    static const ngx_str_t content_type = ngx_string("text/html;charset=utf-8");

    if (html == NULL) {
        html = "<h1>Your connection is being verified<h1><p>Please wait...</p>";
    }

    size_t size = snprintf((char *) buf, sizeof(buf), JS_SOLVER_TEMPLATE, title_c_str, challenge_c_str, html);

    out.buf = b;
    out.next = NULL;

    // TODO: is that stack buffer gonna cause problems?
    b->pos = buf;
    b->last = buf + size;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_SERVICE_UNAVAILABLE;
    r->headers_out.content_length_n = size;
    r->headers_out.content_type = content_type;

    ngx_http_send_header(r);
    ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, 0);

    return NGX_DONE;
}


/*
 * Response is valid if it starts by the challenge, and
 * its SHA1 hash contains the digits 0xB00B at the offset
 * of the first digit
 * And first symbol of response is 0 or 1
 *
 * e.g.
 * challenge =      "CC003677C91D53E29F7095FF90C670C69C7C46E7"
 * response =       "CC003677C91D53E29F7095FF90C670C69C7C46E71579479"
 * SHA1(response) = "011FCCD9ECB2306631FBF530B00B196D0C4AA8AE"
 *                                           ^ offset 24
 */
static int verify_response(ngx_str_t response, char *challenge) {

    // if more then 12 additional chars => wrong
    if (response.len <= SHA1_STR_LEN || response.len > SHA1_STR_LEN + 12) {
        return -1;
    }

    // if first part is not equal to challenge
    if (strncmp(challenge, (char *) response.data, SHA1_STR_LEN) != 0) {
        return -1;
    }

    unsigned char md[SHA1_MD_LEN];
    __sha1((unsigned char *) response.data, response.len, md);

    unsigned int nibble1;
    if (challenge[0] <= '9') {
        nibble1 = challenge[0] - '0';
    } else {
        nibble1 = challenge[0] - 'A' + 10;
    }

    return md[nibble1] == 0xB0 && md[nibble1 + 1] == 0x0B && (md[0] == 0x0 || md[0] == 0x1) ? 0 : -1;
}


static ngx_int_t ngx_http_js_challenge_handler(ngx_http_request_t *r) {
    ngx_http_js_challenge_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_js_challenge_module);

/* 1. Check if Enabled */

    ngx_flag_t is_enabled = conf->enabled;

    // If a variable name was passed instead of a flag
    if (conf->enabled_variable_name.len > 0 && conf->enabled == NGX_CONF_UNSET) {
        ngx_str_t variable_value;

        // Get the value of the variable
        ngx_uint_t key = ngx_hash_strlow(conf->enabled_variable_name.data, conf->enabled_variable_name.data, conf->enabled_variable_name.len);
        ngx_http_variable_value_t *var = ngx_http_get_variable(r, &conf->enabled_variable_name, key);

        if (var == NULL || var->not_found) {
            ngx_str_t *var_name = &conf->enabled_variable_name;
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[js-challenge] variable %*s not found or empty", var_name->len, var_name->data);
            return NGX_DECLINED;
        }

        variable_value.data = var->data;
        variable_value.len = var->len;

        if (ngx_strncmp(variable_value.data, "on", variable_value.len) == 0) {
            is_enabled = 1;
        } else {
            is_enabled = 0;
        }
    }

    if (!is_enabled) {
        return NGX_DECLINED;
    }

/* 2. Check no cookies */

    // Check if 'no_cookie' parameter is present in the query string
    ngx_uint_t no_cookie_present = 0;
    ngx_str_t no_cookie_arg = ngx_string("no_cookie");
    ngx_str_t value;
    if (ngx_http_arg(r, no_cookie_arg.data, no_cookie_arg.len, &value) == NGX_OK) {
        no_cookie_present = 1;
    }

    // Handle the no_cookie case by showing a static error message
    if (no_cookie_present) {
        ngx_buf_t *b = ngx_create_temp_buf(r->pool, 1024);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_chain_t out;
        out.buf = b;
        out.next = NULL;

        b->pos = (u_char *)"<html><head><title>Cookies Required</title></head><body><h1>Cookies Required</h1><p>Please enable cookies in your browser to continue.</p></body></html>";
        b->last = b->pos + strlen((char *)b->pos);
        b->memory = 1;      // memory of the buffer is readonly
        b->last_buf = 1;    // this is the last buffer in the buffer chain

        r->headers_out.status = NGX_HTTP_FORBIDDEN;
        r->headers_out.content_type_len = sizeof("text/html") - 1;
        r->headers_out.content_type.data = (u_char *)"text/html";
        r->headers_out.content_length_n = b->last - b->pos;

        ngx_http_send_header(r);
        ngx_http_output_filter(r, &out);
        ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
        return NGX_HTTP_FORBIDDEN;
    }

/* 3. Get remote client IP */

    // Check for X-REAL-IP header and fallback to connection IP if not present
    ngx_str_t addr = r->connection->addr_text; // Default IP
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;

    for (ngx_uint_t i = 0; i < part->nelts; i++) {
        if ((ngx_strncasecmp(header[i].key.data, (u_char *)"X-REAL-IP", header[i].key.len) == 0 ||
             ngx_strncasecmp(header[i].key.data, (u_char *)"X-FORWARDED-FOR", header[i].key.len) == 0) &&
            header[i].value.len > 0 && header[i].value.len <= 39) {
            // Convert ngx_str_t to NULL-terminated string for is_private_ip
            char ip_str[40];
            ngx_cpystrn((u_char *)ip_str, addr.data, addr.len + 1);
            if (is_private_ip(ip_str)) {
                addr = header[i].value;
                break;
            }
        }
        if (i == part->nelts - 1 && part->next != NULL) {
            part = part->next;
            header = part->elts;
            i = -1;
        }
    }

/* 4. Get User-Agent */

    // Extract User-Agent header
    ngx_str_t user_agent = {0, NULL};  // Initialize ngx_str_t with default values.
    if (r && r->headers_in.user_agent) {
        user_agent = r->headers_in.user_agent->value;
    }

/* 5. Get Challenge */

    unsigned long bucket = r->start_sec - (r->start_sec % conf->bucket_duration);

    char challenge[SHA1_STR_LEN];
    get_challenge_string(bucket, addr, user_agent, conf->secret, challenge);  // Updated to include User-Agent

/* 6. Check Challenge response */

    ngx_str_t response;
    ngx_str_t cookie_name = ngx_string("c_token");
    int ret = get_cookie(r, &cookie_name, &response);

    // no cookie received
    if (ret != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[js-challenge] new c_token: %s ", challenge);
        conf->challenge_served = 1;
        return serve_challenge(r, challenge, conf->html, conf->title);
    }

    // wrong challenge-response in cookies
    if (verify_response(response, challenge) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[js-challenge] wrong/expired c_token (%s), update c_token: %s", response.data, challenge);
        conf->challenge_served = 1;
        return serve_challenge(r, challenge, conf->html, conf->title);
    }

    // Fallthrough next handler
    return NGX_DECLINED;
}


static ngx_int_t ngx_http_js_challenge_served_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_js_challenge_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_js_challenge_module);

    if (conf->challenge_served) {
        v->len = 1;
        v->data = (u_char *) "1";
    } else {
        v->len = 1;
        v->data = (u_char *) "0";
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

/**
 * post configuration
 */
static ngx_int_t ngx_http_js_challenge(ngx_conf_t *cf) {
    ngx_http_variable_t *var;

    for (var = ngx_http_js_challenge_vars; var->name.len; var++) {
        ngx_http_variable_t *v = ngx_http_add_variable(cf, &var->name, var->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }
        v->get_handler = var->get_handler;
        v->data = var->data;
    }

    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&main_conf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "null");
        return NGX_ERROR;
    }

    *h = ngx_http_js_challenge_handler;

    return NGX_OK;
}

/////////////////////////////

ngx_inline static int is_private_ip(const char *ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return 0; // Not a valid IP address
    }
    uint32_t host_addr = ntohl(addr.s_addr);

    if (((host_addr & 0xFF000000) == 0x0A000000) || // 10.0.0.0/8
        ((host_addr & 0xFFF00000) == 0xAC100000) || // 172.16.0.0/12
        ((host_addr & 0xFFFF0000) == 0xC0A80000)) { // 192.168.0.0/16
        return 1;
    }

    return 0; // IP is not within the private ranges
}


static int get_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value) {
#if defined(nginx_version) && nginx_version >= 1023000
    ngx_table_elt_t *h;
    for (h = r->headers_in.cookie; h; h = h->next) {
        u_char *start = h->value.data;
        u_char *end = h->value.data + h->value.len;
#else
    ngx_table_elt_t **h;
    h = r->headers_in.cookies.elts;

    ngx_uint_t i = 0;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        u_char *start = h[i]->value.data;
        u_char *end = h[i]->value.data + h[i]->value.len;
#endif
        while (start < end) {
            while (start < end && *start == ' ') { start++; }

            if (ngx_strncmp(start, name->data, name->len) == 0) {
                u_char *last;
                for (last = start; last < end && *last != ';'; last++) {}
                while (*start++ != '=' && start < last) {}

                value->data = start;
                value->len = (last - start);
                return 0;
            }
            while (*start++ != ';' && start < end) {}
        }
    }

    return -1;
}

static unsigned char *__sha1(const unsigned char *d, size_t n, unsigned char *md) {
    ngx_sha1_t c;
    ngx_sha1_init(&c);
    ngx_sha1_update(&c, d, n);
    ngx_sha1_final(md, &c);
    return md;
}

ngx_inline static void buf2hex(const unsigned char *buf, size_t buflen, char *hex_string) {
    static const char hexdig[] = "0123456789ABCDEF";
    const unsigned char *p;
    size_t i;
    char *s = hex_string;
    for (i = 0, p = buf; i < buflen; i++, p++) {
        *s++ = hexdig[(*p >> 4) & 0x0f];
        *s++ = hexdig[*p & 0x0f];
    }
}
