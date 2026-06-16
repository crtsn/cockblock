#include "cJSON.h"

static const char *last_error = NULL;

/* ── Input buffer ── */
typedef struct {
    const char *s;
    size_t len, pos;
} inbuf;

static char ib_peek(inbuf *b) { return b->pos < b->len ? b->s[b->pos] : 0; }
static char ib_next(inbuf *b) { return b->pos < b->len ? b->s[b->pos++] : 0; }
static void ib_skip_ws(inbuf *b) {
    while (b->pos < b->len) {
        char c = b->s[b->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') b->pos++;
        else break;
    }
}

/* ── Forward declarations ── */
static cJSON *parse_value(inbuf *b);

/* ── Parse string (opening quote already consumed) ── */
static cJSON *parse_string_raw(inbuf *b) {
    cJSON *item = calloc(1, sizeof(cJSON));
    item->type = cJSON_String;
    size_t cap = 64, len = 0;
    char *buf = malloc(cap);

    while (b->pos < b->len) {
        char c = ib_next(b);
        if (c == '"') break;
        if (c == '\\') {
            c = ib_next(b);
            switch (c) {
                case '"': case '\\': case '/': break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'u': {
                    char hex[5] = {0};
                    for (int i = 0; i < 4 && b->pos < b->len; i++)
                        hex[i] = ib_next(b);
                    unsigned int cp = (unsigned int)strtoul(hex, NULL, 16);
                    if (cp < 0x80) {
                        c = (char)cp;
                    } else if (cp < 0x800) {
                        if (len + 2 >= cap) { cap *= 2; buf = realloc(buf, cap); }
                        buf[len++] = (char)(0xC0 | (cp >> 6));
                        buf[len++] = (char)(0x80 | (cp & 0x3F));
                        continue;
                    } else {
                        if (len + 3 >= cap) { cap *= 2; buf = realloc(buf, cap); }
                        buf[len++] = (char)(0xE0 | (cp >> 12));
                        buf[len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        buf[len++] = (char)(0x80 | (cp & 0x3F));
                        continue;
                    }
                }
            }
        }
        if (len + 1 >= cap) { cap *= 2; buf = realloc(buf, cap); }
        buf[len++] = c;
    }
    buf[len] = 0;
    item->valuestring = buf;
    return item;
}

/* ── Parse number ── */
static cJSON *parse_number(inbuf *b) {
    cJSON *item = calloc(1, sizeof(cJSON));
    item->type = cJSON_Number;
    size_t start = b->pos;
    if (ib_peek(b) == '-') b->pos++;
    while (b->pos < b->len && b->s[b->pos] >= '0' && b->s[b->pos] <= '9') b->pos++;
    if (b->pos < b->len && b->s[b->pos] == '.') {
        b->pos++;
        while (b->pos < b->len && b->s[b->pos] >= '0' && b->s[b->pos] <= '9') b->pos++;
    }
    if (b->pos < b->len && (b->s[b->pos] == 'e' || b->s[b->pos] == 'E')) {
        b->pos++;
        if (b->pos < b->len && (b->s[b->pos] == '+' || b->s[b->pos] == '-')) b->pos++;
        while (b->pos < b->len && b->s[b->pos] >= '0' && b->s[b->pos] <= '9') b->pos++;
    }
    char tmp[64];
    size_t slen = b->pos - start;
    if (slen >= sizeof(tmp)) slen = sizeof(tmp) - 1;
    memcpy(tmp, b->s + start, slen);
    tmp[slen] = 0;
    item->valuedouble = atof(tmp);
    item->valueint = (int)item->valuedouble;
    return item;
}

/* ── Parse literal (true / false / null) ── */
static cJSON *parse_literal(inbuf *b) {
    if (strncmp(b->s + b->pos, "true", 4) == 0) {
        b->pos += 4;
        cJSON *item = calloc(1, sizeof(cJSON));
        item->type = cJSON_True;
        item->valuedouble = 1;
        item->valueint = 1;
        return item;
    }
    if (strncmp(b->s + b->pos, "false", 5) == 0) {
        b->pos += 5;
        cJSON *item = calloc(1, sizeof(cJSON));
        item->type = cJSON_False;
        return item;
    }
    if (strncmp(b->s + b->pos, "null", 4) == 0) {
        b->pos += 4;
        cJSON *item = calloc(1, sizeof(cJSON));
        item->type = cJSON_NULL;
        return item;
    }
    last_error = &b->s[b->pos];
    return NULL;
}

/* ── Parse array ── */
static cJSON *parse_array(inbuf *b) {
    ib_next(b); /* consume '[' */
    cJSON *head = NULL, *tail = NULL;
    ib_skip_ws(b);

    if (ib_peek(b) == ']') {
        ib_next(b);
        cJSON *item = calloc(1, sizeof(cJSON));
        item->type = cJSON_Array;
        return item;
    }

    while (1) {
        ib_skip_ws(b);
        cJSON *val = parse_value(b);
        if (!val) {
            if (last_error == NULL) last_error = &b->s[b->pos];
            cJSON_Delete(head); return NULL;
        }
        val->prev = tail;
        if (tail) tail->next = val;
        else head = val;
        tail = val;

        ib_skip_ws(b);
        if (ib_peek(b) == ',') { ib_next(b); continue; }
        break;
    }

    ib_skip_ws(b);
    if (ib_peek(b) == ']') ib_next(b);

    cJSON *arr = calloc(1, sizeof(cJSON));
    arr->type = cJSON_Array;
    arr->child = head;
    return arr;
}

/* ── Parse object ── */
static cJSON *parse_object(inbuf *b) {
    ib_next(b); /* consume '{' */
    cJSON *head = NULL, *tail = NULL;
    ib_skip_ws(b);

    if (ib_peek(b) == '}') {
        ib_next(b);
        cJSON *item = calloc(1, sizeof(cJSON));
        item->type = cJSON_Object;
        return item;
    }

    while (1) {
        ib_skip_ws(b);
        if (ib_peek(b) != '"') {
            last_error = &b->s[b->pos];
            cJSON_Delete(head); return NULL;
        }
        ib_next(b);  /* consume opening quote for key string */
        cJSON *key = parse_string_raw(b);
        if (!key) { cJSON_Delete(head); return NULL; }

        ib_skip_ws(b);
        if (ib_peek(b) != ':') {
            last_error = &b->s[b->pos];
            free(key->valuestring); free(key);
            cJSON_Delete(head); return NULL;
        }
        ib_next(b); /* consume ':' */

        ib_skip_ws(b);
        cJSON *val = parse_value(b);
        if (!val) {
            if (last_error == NULL) last_error = &b->s[b->pos];
            free(key->valuestring); free(key);
            cJSON_Delete(head); return NULL;
        }

        val->string = key->valuestring;
        key->valuestring = NULL;
        free(key);

        val->prev = tail;
        if (tail) tail->next = val;
        else head = val;
        tail = val;

        ib_skip_ws(b);
        if (ib_peek(b) == ',') { ib_next(b); continue; }
        break;
    }

    ib_skip_ws(b);
    if (ib_peek(b) == '}') ib_next(b);

    cJSON *obj = calloc(1, sizeof(cJSON));
    obj->type = cJSON_Object;
    obj->child = head;
    return obj;
}

/* ── Parse value ── */
static cJSON *parse_value(inbuf *b) {
    ib_skip_ws(b);
    char c = ib_peek(b);
    if (c == '"') { ib_next(b); return parse_string_raw(b); }
    if (c == '{') return parse_object(b);
    if (c == '[') return parse_array(b);
    if (c == 't' || c == 'f' || c == 'n') return parse_literal(b);
    if (c == '-' || (c >= '0' && c <= '9')) return parse_number(b);
    last_error = &b->s[b->pos];
    return NULL;
}

/* ══════════════════════════════════════════════════
   Public API
   ══════════════════════════════════════════════════ */

cJSON *cJSON_Parse(const char *text) {
    if (!text) return NULL;
    inbuf b = { text, strlen(text), 0 };
    last_error = NULL;
    return parse_value(&b);
}

const char *cJSON_GetErrorPtr(void) {
    return last_error;
}

void cJSON_Delete(cJSON *c) {
    while (c) {
        cJSON *next = c->next;
        if (c->child) cJSON_Delete(c->child);
        free(c->valuestring);
        free(c->string);
        free(c);
        c = next;
    }
}

cJSON *cJSON_GetObjectItem(const cJSON *object, const char *string) {
    if (!object || !string) return NULL;
    cJSON *c = object->child;
    while (c && c->string) {
        if (strcmp(c->string, string) == 0) return c;
        c = c->next;
    }
    return NULL;
}

int cJSON_GetArraySize(const cJSON *array) {
    if (!array) return 0;
    int n = 0;
    cJSON *c = array->child;
    while (c) { n++; c = c->next; }
    return n;
}

cJSON *cJSON_GetArrayItem(const cJSON *array, int index) {
    if (!array) return NULL;
    cJSON *c = array->child;
    while (c && index > 0) { c = c->next; index--; }
    return c;
}

cJSON *cJSON_CreateTrue(void) {
    cJSON *i = calloc(1, sizeof(cJSON));
    i->type = cJSON_True; i->valuedouble = 1; i->valueint = 1;
    return i;
}

cJSON *cJSON_CreateFalse(void) {
    cJSON *i = calloc(1, sizeof(cJSON));
    i->type = cJSON_False;
    return i;
}

cJSON *cJSON_CreateString(const char *string) {
    cJSON *i = calloc(1, sizeof(cJSON));
    i->type = cJSON_String;
    i->valuestring = strdup(string);
    return i;
}

cJSON *cJSON_CreateNumber(double num) {
    cJSON *i = calloc(1, sizeof(cJSON));
    i->type = cJSON_Number;
    i->valuedouble = num;
    i->valueint = (int)num;
    return i;
}

cJSON *cJSON_CreateObject(void) {
    cJSON *i = calloc(1, sizeof(cJSON));
    i->type = cJSON_Object;
    return i;
}

cJSON *cJSON_CreateArray(void) {
    cJSON *i = calloc(1, sizeof(cJSON));
    i->type = cJSON_Array;
    return i;
}

static cJSON *get_last(cJSON *c) {
    if (!c || !c->child) return NULL;
    cJSON *p = c->child;
    while (p->next) p = p->next;
    return p;
}

void cJSON_AddItemToArray(cJSON *array, cJSON *item) {
    if (!array || !item) return;
    cJSON *last = get_last(array);
    if (last) { last->next = item; item->prev = last; }
    else array->child = item;
}

void cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item) {
    if (!object || !string || !item) return;
    free(item->string);
    item->string = strdup(string);
    cJSON_AddItemToArray(object, item);
}

int cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newitem) {
    cJSON *existing = cJSON_GetObjectItem(object, string);
    if (!existing) return 0;
    free(newitem->string);
    newitem->string = strdup(string);
    newitem->prev = existing->prev;
    newitem->next = existing->next;
    if (existing->prev) existing->prev->next = newitem;
    else if (object->child == existing) object->child = newitem;
    if (existing->next) existing->next->prev = newitem;
    existing->next = NULL;
    existing->prev = NULL;
    cJSON_Delete(existing);
    return 1;
}

/* ══════════════════════════════════════════════════
   Print / serialize
   ══════════════════════════════════════════════════ */

typedef struct {
    char *buf;
    size_t len, cap;
} outbuf;

static void ob_init(outbuf *o) {
    o->cap = 256; o->len = 0;
    o->buf = malloc(o->cap);
    o->buf[0] = 0;
}

static void ob_append(outbuf *o, const char *s, size_t n) {
    while (o->len + n + 1 > o->cap) { o->cap *= 2; o->buf = realloc(o->buf, o->cap); }
    memcpy(o->buf + o->len, s, n);
    o->len += n;
    o->buf[o->len] = 0;
}

static void ob_appendc(outbuf *o, char c) { ob_append(o, &c, 1); }

static void print_string(outbuf *o, const char *s) {
    ob_appendc(o, '"');
    for (; *s; s++) {
        switch (*s) {
            case '"':  ob_append(o, "\\\"", 2); break;
            case '\\': ob_append(o, "\\\\", 2); break;
            case '\b': ob_append(o, "\\b", 2);  break;
            case '\f': ob_append(o, "\\f", 2);  break;
            case '\n': ob_append(o, "\\n", 2);  break;
            case '\r': ob_append(o, "\\r", 2);  break;
            case '\t': ob_append(o, "\\t", 2);  break;
            default:
                if ((unsigned char)*s < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)*s);
                    ob_append(o, buf, 6);
                } else {
                    ob_appendc(o, *s);
                }
        }
    }
    ob_appendc(o, '"');
}

static void print_value(outbuf *o, const cJSON *item);

static void print_array(outbuf *o, const cJSON *arr) {
    ob_appendc(o, '[');
    const cJSON *c = arr->child;
    while (c) {
        print_value(o, c);
        if (c->next) ob_appendc(o, ',');
        c = c->next;
    }
    ob_appendc(o, ']');
}

static void print_object(outbuf *o, const cJSON *obj) {
    ob_appendc(o, '{');
    const cJSON *c = obj->child;
    while (c) {
        if (c->string) {
            print_string(o, c->string);
            ob_appendc(o, ':');
        }
        print_value(o, c);
        if (c->next) ob_appendc(o, ',');
        c = c->next;
    }
    ob_appendc(o, '}');
}

static void print_value(outbuf *o, const cJSON *item) {
    if (!item) { ob_append(o, "null", 4); return; }
    switch (item->type) {
        case cJSON_False: ob_append(o, "false", 5); break;
        case cJSON_True:  ob_append(o, "true", 4);  break;
        case cJSON_NULL:  ob_append(o, "null", 4);  break;
        case cJSON_Number: {
            char buf[64];
            long iv = (long)item->valuedouble;
            if ((double)iv == item->valuedouble)
                snprintf(buf, sizeof(buf), "%ld", iv);
            else
                snprintf(buf, sizeof(buf), "%g", item->valuedouble);
            ob_append(o, buf, strlen(buf));
            break;
        }
        case cJSON_String:
            print_string(o, item->valuestring ? item->valuestring : "");
            break;
        case cJSON_Array:  print_array(o, item);  break;
        case cJSON_Object: print_object(o, item); break;
    }
}

char *cJSON_Print(const cJSON *item) {
    outbuf o;
    ob_init(&o);
    print_value(&o, item);
    return o.buf;
}
