#define LUA_LIB

#include "skynet_malloc.h"

#include "skynet_socket.h"

#include <lua.h>
#include <lauxlib.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>


#include "base64.h"  
#include "sha1.h"  
#include "intLib.h"  

#define QUEUESIZE 1024
#define HASHSIZE 4096
#define HASHSIZE2 4096
#define SMALLSTRING 2048

#define TYPE_DATA 1
#define TYPE_MORE 2
#define TYPE_ERROR 3
#define TYPE_OPEN 4
#define TYPE_CLOSE 5
#define TYPE_WARNING 6

//static int shake_handed = 0;
//static uint8_t shake_handed_buf[2048] = { 0 };
//static int shake_handed_buf_len = 0;
/*
Each package is uint16 + data , uint16 (serialized in big-endian) is the number of bytes comprising the data .
*/

#define nn_debug_free  skynet_free//__noop //((void)0)// skynet_free

struct netpack {
	int id;
	int size;
	void * buffer;
};

#define ALLOW_WEBSOCKET_SHAKE_HANDED_MAX_DATA_LEN 2048
struct nn_list{
	int id;
	struct nn_list * next;
};
//
//struct nn_hash {
//	struct nn_list * hash[HASHSIZE2];
//};
//struct nn_hash * pnn_hash = 0;

#define HEAD_LEN_MAX 9//最大需9字节
struct uncomplete {
	struct netpack pack;
	struct uncomplete * next;
	int read;
	//uint8_t is_handshark;
	uint8_t header[HEAD_LEN_MAX];
};

struct queue {
	int cap;
	int head;
	int tail;
	//uint8_t is_handshark;
	//struct nn_hash * pnn_hash;
	struct nn_list * handshark_hash[HASHSIZE2];
	struct uncomplete * hash[HASHSIZE];
	struct netpack queue[QUEUESIZE];
};


static inline int
hash_fd2(int fd) {
	int a = fd >> 24;
	int b = fd >> 12;
	int c = fd;
	return (int)(((uint32_t)(a + b + c)) % HASHSIZE2);
}


static struct nn_list *
find_nn_list(struct queue* q, int fd) {
	int h = hash_fd2(fd);
	struct nn_list * uc = q->handshark_hash[h];
	if (uc == NULL)
		return NULL;
	if (uc->id == fd) {
		return uc;
	}
	struct nn_list * last = uc;
	while (last->next) {
		uc = last->next;
		if (uc->id == fd) {
			return uc;
		}
		last = uc;
	}
	return NULL;
}

static void add_nn_list(struct queue* q, int fd){
	int h = hash_fd2(fd);
	struct nn_list * uc = q->handshark_hash[h];
	uc = skynet_malloc(sizeof(struct nn_list));
	memset(uc, sizeof(struct nn_list), 0);
	uc->id = fd;
	uc->next = q->handshark_hash[h];
	q->handshark_hash[h] = uc;
}

static void remove_nn_list(struct queue* q, int fd){
	if (!q){
		return;
	}
	int h = hash_fd2(fd);
	struct nn_list * uc = q->handshark_hash[h];
	if (uc == NULL)
		//assert(0);
		return;
	if (uc->id == fd) {
		q->handshark_hash[h] = uc->next;
		nn_debug_free(uc);
		return;
	}
	struct nn_list * last = uc;
	while (last->next) {
		uc = last->next;
		if (uc->id == fd) {
			last->next = uc->next;
			nn_debug_free(uc);
			return;
		}
		last = uc;
	}
	//assert(0);
}


#define REQUEST_LEN_MAX 1024  
#define DEFEULT_SERVER_PORT 80//00  
#define WEB_SOCKET_KEY_LEN_MAX 256  
#define RESPONSE_HEADER_LEN_MAX 1024  
char * fetchSecKey(const char * buf)
{
	char *key;
	char *keyBegin;
	char *flag = "Sec-WebSocket-Key: ";
	int i = 0, bufLen = 0;

	key = (char *)malloc(WEB_SOCKET_KEY_LEN_MAX);
	memset(key, 0, WEB_SOCKET_KEY_LEN_MAX);
	if (!buf)
	{
		return NULL;
	}

	keyBegin = strstr(buf, flag);
	if (!keyBegin)
	{
		return NULL;
	}
	keyBegin += strlen(flag);

	bufLen = strlen(buf);
	for (i = 0; i<bufLen; i++)
	{
		if (keyBegin[i] == 0x0A || keyBegin[i] == 0x0D)
		{
			break;
		}
		key[i] = keyBegin[i];
	}

	return key;
}

#define LINE_MAX 256  
char * computeAcceptKey(const char * buf)
{
	char * clientKey;
	char * serverKey;
	char * sha1DataTemp;
	char * sha1Data;
	short temp;
	int i, n;
	const char * GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";


	if (!buf)
	{
		return NULL;
	}
	clientKey = (char *)malloc(LINE_MAX);
	memset(clientKey, 0, LINE_MAX);
	clientKey = fetchSecKey(buf);

	if (!clientKey)
	{
		return NULL;
	}

	strcat_s(clientKey, LINE_MAX, GUID);

	sha1DataTemp = sha1_hash(clientKey);
	n = strlen(sha1DataTemp);


	sha1Data = (char *)malloc(n / 2 + 1);
	memset(sha1Data, 0, n / 2 + 1);

	for (i = 0; i<n; i += 2)
	{
		sha1Data[i / 2] = htoi(sha1DataTemp, i, 2);
	}

	serverKey = base64_encode(sha1Data, strlen(sha1Data));

	return serverKey;
}

void shakeHand(const char *serverKey, struct uncomplete * uc)
{
	assert(serverKey && uc);
	char* responseHeader = (char*)uc->pack.buffer;
	memset(responseHeader, '\0', ALLOW_WEBSOCKET_SHAKE_HANDED_MAX_DATA_LEN);
	//sprintf_s(responseHeader, ALLOW_WEBSOCKET_SHAKE_HANDED_MAX_DATA_LEN, "HTTP/1.1 101 Switching Protocols\r\n");
	//sprintf_s(responseHeader, ALLOW_WEBSOCKET_SHAKE_HANDED_MAX_DATA_LEN, "%sUpgrade: websocket\r\n", responseHeader);
	//sprintf_s(responseHeader, ALLOW_WEBSOCKET_SHAKE_HANDED_MAX_DATA_LEN, "%sConnection: Upgrade\r\n", responseHeader);
	//sprintf_s(responseHeader, ALLOW_WEBSOCKET_SHAKE_HANDED_MAX_DATA_LEN, "%sSec-WebSocket-Accept: %s\r\n\r\n", responseHeader, serverKey);
	strcpy(responseHeader, "HTTP/1.1 101 Switching Protocols\r\n");
	strcat(responseHeader, "Upgrade: websocket\r\n");
	strcat(responseHeader, "Connection: Upgrade\r\n");
	strcat(responseHeader, "Sec-WebSocket-Accept: ");
	strcat(responseHeader, serverKey);
	strcat(responseHeader, "\r\n\r\n");

	//printf("Response Header:%s\n", responseHeader);

	//write(connfd, responseHeader, strlen(responseHeader));
	uc->pack.size = strlen(responseHeader);
	//memcpy(uc->pack.buffer, responseHeader, uc->pack.size);
	//shake_handed_buf[shake_handed_buf_len] = 0;
}


static void
clear_list(struct uncomplete * uc) {
	while (uc) {
		skynet_free(uc->pack.buffer);
		void * tmp = uc;
		uc = uc->next;
		skynet_free(tmp);
	}
}

static int
lclear(lua_State *L) {
	struct queue * q = lua_touserdata(L, 1);
	if (q == NULL) {
		return 0;
	}
	int i;
	for (i = 0; i<HASHSIZE; i++) {
		clear_list(q->hash[i]);
		q->hash[i] = NULL;
	}
	if (q->head > q->tail) {
		q->tail += q->cap;
	}
	for (i = q->head; i<q->tail; i++) {
		struct netpack *np = &q->queue[i % q->cap];
		skynet_free(np->buffer);
	}
	q->head = q->tail = 0;

	return 0;
}

static inline int
hash_fd(int fd) {
	int a = fd >> 24;
	int b = fd >> 12;
	int c = fd;
	return (int)(((uint32_t)(a + b + c)) % HASHSIZE);
}

static struct uncomplete *
find_uncomplete(struct queue *q, int fd) {
	if (q == NULL)
		return NULL;
	int h = hash_fd(fd);
	struct uncomplete * uc = q->hash[h];
	if (uc == NULL)
		return NULL;
	if (uc->pack.id == fd) {
		q->hash[h] = uc->next;
		return uc;
	}
	struct uncomplete * last = uc;
	while (last->next) {
		uc = last->next;
		if (uc->pack.id == fd) {
			last->next = uc->next;
			return uc;
		}
		last = uc;
	}
	return NULL;
}

static struct queue *
get_queue(lua_State *L) {
	struct queue *q = lua_touserdata(L, 1);
	if (q == NULL) {
		q = lua_newuserdata(L, sizeof(struct queue));
		q->cap = QUEUESIZE;
		q->head = 0;
		q->tail = 0;
		//q->is_handshark = 0;
		int i;
		for (i = 0; i < HASHSIZE2; i++)
		{
			q->handshark_hash[i] = NULL;
		}
		for (i = 0; i<HASHSIZE; i++) {
			q->hash[i] = NULL;
		}
		lua_replace(L, 1);
	}
	return q;
}

static void insert_uncomplete(struct queue *q, struct uncomplete * uc) {
	int fd = uc->pack.id;

	int h = hash_fd(fd);
	uc->next = q->hash[h];
	q->hash[h] = uc;
}

static void add_uncomplete(lua_State *L, struct uncomplete * uc) {
	struct queue *q = get_queue(L);
	insert_uncomplete(q, uc);
}

static void
expand_queue(lua_State *L, struct queue *q) {
	struct queue *nq = lua_newuserdata(L, sizeof(struct queue) + q->cap * sizeof(struct netpack));
	nq->cap = q->cap + QUEUESIZE;
	nq->head = 0;
	nq->tail = q->cap;
	memcpy(nq->hash, q->hash, sizeof(nq->hash));
	memset(q->hash, 0, sizeof(q->hash));
	int i;
	for (i = 0; i<q->cap; i++) {
		int idx = (q->head + i) % q->cap;
		nq->queue[i] = q->queue[idx];
	}
	q->head = q->tail = 0;
	lua_replace(L, 1);
}

static void
push_data(lua_State *L, int fd, void *buffer, int size, int clone) {
	if (clone) {
		void * tmp = skynet_malloc(size);
		memcpy(tmp, buffer, size);
		buffer = tmp;
	}
	struct queue *q = get_queue(L);
	struct netpack *np = &q->queue[q->tail];
	if (++q->tail >= q->cap)
		q->tail -= q->cap;
	np->id = fd;
	np->buffer = buffer;
	np->size = size;
	if (q->head == q->tail) {
		expand_queue(L, q);
	}
}

static struct uncomplete *
new_uncomplete(int fd) {
	struct uncomplete * uc = skynet_malloc(sizeof(struct uncomplete));
	memset(uc, 0, sizeof(*uc));
	uc->pack.id = fd;

	return uc;
}

static struct uncomplete *
save_uncomplete(lua_State *L, int fd) {
	struct queue *q = get_queue(L);
	struct uncomplete * uc = new_uncomplete(fd);
	insert_uncomplete(q, uc);

	return uc;
}

#define DATA_LESS 1
#define DATA_MORE 2
#define DATA_OK 5
#define DATA_ERR -1//自定义
#define HEAD_LESS -2
#define CONNECTION_CLOSE -3
static inline int
read_size(uint8_t * buffer, int size) {
	int r = 0;// (int)buffer[0] << 8 | (int)buffer[1];
	const char * buf = buffer;
	char * data;
	char fin, Opcode, maskFlag, masks[4];
	char * payloadData;
	char temp[8];
	unsigned long n, payloadLen = 0;
	unsigned short usLen = 0;
	int i = 0;
	int extended_pay_load_length = 0;

	if (size < 2){
		return HEAD_LESS;
	}

	fin = (buf[0] & 0x80) == 0x80; // 1bit，1表示最后一帧    
	if (!fin)
	{
		assert(0);
		return DATA_ERR;// 超过一帧暂不处理   
	}
	Opcode = (buf[0] & 0xF);
	if (0x8 == Opcode)//*  %x8 denotes a connection close
	{
		return CONNECTION_CLOSE;
	}
	maskFlag = (buf[1] & 0x80) == 0x80; // 是否包含掩码    
	if (!maskFlag)
	{
		assert(0);
		return DATA_ERR;// 不包含掩码的暂不处理  
	}

	payloadLen = buf[1] & 0x7F; // 数据长度   
	if (payloadLen == 126)
	{
		if (size < 4)
		{
			return HEAD_LESS;
		}
		extended_pay_load_length = 1;
		payloadLen = (buf[2] & 0xFF) << 8 | (buf[3] & 0xFF);
	}
	else if (payloadLen == 127)
	{
		if (size < HEAD_LEN_MAX)
		{
			return HEAD_LESS;
		}
		extended_pay_load_length = 4;
		for (i = 0; i < 8; i++)
		{
			temp[i] = buf[9 - i];
		}

		memcpy(&n, temp, 8);
		payloadLen = n;
	}
	r = payloadLen;

	return r + sizeof(masks) + extended_pay_load_length;
}

char * get_payload_data(const char * buf, const int pack_size, unsigned long* p_payloadLen)
{
	const int bufLen = pack_size;
	char * data;
	char masks[4];
	char * payloadData;
	char temp[8];
	unsigned long n, payloadLen = 0;
	unsigned short usLen = 0;
	int i = 0;

	payloadLen = buf[1] & 0x7F; // 数据长度   
	if (payloadLen == 126)
	{
		memcpy(masks, buf + 4, 4);
		payloadLen = (buf[2] & 0xFF) << 8 | (buf[3] & 0xFF);
		payloadData = (char *)skynet_malloc(payloadLen);
		memset(payloadData, 0, payloadLen);
		memcpy(payloadData, buf + 8, payloadLen);
	}
	else if (payloadLen == 127)
	{
		memcpy(masks, buf + 10, 4);
		for (i = 0; i < 8; i++)
		{
			temp[i] = buf[9 - i];
		}

		memcpy(&n, temp, 8);
		payloadLen = n;
		payloadData = (char *)skynet_malloc(payloadLen);
		memset(payloadData, 0, n);
		memcpy(payloadData, buf + 14, n);//toggle error(core dumped) if data is too long.  
	}
	else
	{
		memcpy(masks, buf + 2, 4);
		payloadData = (char *)skynet_malloc(payloadLen);
		memset(payloadData, 0, payloadLen);
		memcpy(payloadData, buf + 6, payloadLen);
	}

	for (i = 0; i < payloadLen; i++)
	{
		payloadData[i] = (char)(payloadData[i] ^ masks[i % 4]);
	}

	//printf("data(%d):%s\n", payloadLen, payloadData);
	*p_payloadLen = payloadLen;
	return payloadData;
}

static void
push_more(lua_State *L, int fd, uint8_t *buffer, int size) {
	int pack_size = read_size(buffer, size);
	if (0 > pack_size){
		struct uncomplete * uc = save_uncomplete(L, fd);
		uc->read = -size;
		memcpy(uc->header, buffer, size);
		return;
	}

	if (size < pack_size) {
		struct uncomplete * uc = save_uncomplete(L, fd);
		uc->read = size;
		uc->pack.size = pack_size;
		uc->pack.buffer = skynet_malloc(pack_size);
		memcpy(uc->pack.buffer, buffer, size);
		return;
	}
	unsigned long payloadLen = 0;
	void * result = get_payload_data(buffer, size, &payloadLen);
	push_data(L, fd, buffer, pack_size, 0);

	buffer += pack_size;
	size -= pack_size;
	if (size > 0) {
		push_more(L, fd, buffer, size);
	}
}

static void
close_uncomplete(lua_State *L, int fd) {
	struct queue *q = lua_touserdata(L, 1);
	struct uncomplete * uc = find_uncomplete(q, fd);
	if (uc) {
		skynet_free(uc->pack.buffer);
		skynet_free(uc);
	}
}
#ifndef min
#define max(a,b)    (((a) > (b)) ? (a) : (b))
#define min(a,b)    (((a) < (b)) ? (a) : (b))
#endif  /* __cplusplus */

#define HTTP_END_STRING "\r\n\r\n"
static int
filter_data_(lua_State *L, int fd, uint8_t * buffer, int size) {
	struct queue *q = lua_touserdata(L, 1);
	struct uncomplete * uc = find_uncomplete(q, fd);
	const char * buf = buffer;
	const int bufLen = size;
	int pack_size = 0;
	unsigned long n, payloadLen = 0;
	char* pos = NULL;

	//处理websocket握手协议
	if (!q || !find_nn_list(q, fd))// || !q->is_handshark) //(!find_nn_list(fd)) //是否已经握手成功过
	{
		printf("0x%08x, fd:%d\r\n", q, fd);
		if (!uc){
			uc = new_uncomplete(fd);
			uc->read = 0;
			uc->pack.buffer = skynet_malloc(ALLOW_WEBSOCKET_SHAKE_HANDED_MAX_DATA_LEN);
		}
		memcpy(((char*)uc->pack.buffer) + uc->read, buffer, size);
		uc->read += size;
		((char*)uc->pack.buffer)[uc->read] = 0;
		pos = strstr((char*)uc->pack.buffer, HTTP_END_STRING);
		if (!pos){
			add_uncomplete(L, uc);
			return DATA_LESS;
		}
		assert(pos + strlen(HTTP_END_STRING) == (char*)uc->pack.buffer + uc->read);

		printf("read:%d\n%s\n", uc->read, (char*)uc->pack.buffer);
		char *secWebSocketKey;
		secWebSocketKey = computeAcceptKey((char*)uc->pack.buffer);
		if (!secWebSocketKey){
			//close_uncomplete(L, fd);
			skynet_free(uc->pack.buffer);
			skynet_free(uc);
			lua_pushvalue(L, lua_upvalueindex(TYPE_CLOSE));
			lua_pushinteger(L, fd);
			//shake_handed = 0;
			//shake_handed_buf_len = 0;
			return 3;
		}

		shakeHand(secWebSocketKey, uc);
		void * result = skynet_malloc(uc->pack.size);
		memcpy(result, uc->pack.buffer, uc->pack.size);

		lua_pushvalue(L, lua_upvalueindex(TYPE_DATA));
		lua_pushinteger(L, fd);
		lua_pushlightuserdata(L, result);
		lua_pushinteger(L, uc->pack.size);
		skynet_free(uc->pack.buffer);
		skynet_free(uc);

		if (!q){
			q = get_queue(L);
		}
		add_nn_list(q, fd);
		//q->is_handshark = 1;

		return DATA_OK;
	}

	if (uc) {
		// fill uncomplete
		if (uc->read < 0) {
			// read size
			assert(uc->read > -HEAD_LEN_MAX);
			uint8_t header[HEAD_LEN_MAX] = { 0 };
			memcpy(header, uc->header, -uc->read);
			int len = min((sizeof(header) + uc->read), size);
			memcpy(&header[-uc->read], buffer, len);
			len += -uc->read;
			int pack_size = read_size(header, len);
			if (0 > pack_size){
				memcpy(&header[-uc->read], buffer, min((sizeof(header) + uc->read), size));
				uc->read = -len;
				return DATA_LESS;
			}
			int total_size = -uc->read + size;
			if (total_size < pack_size){
				uc->pack.size = pack_size;
				uc->pack.buffer = skynet_malloc(pack_size);
				memcpy(uc->pack.buffer, uc->header, -uc->read);
				memcpy((char*)uc->pack.buffer - uc->read, buffer, size);
				uc->read = len;
				return DATA_LESS;
			}

			char buf_tmp = skynet_malloc(pack_size);
			memcpy(buf_tmp, uc->header, -uc->read);
			memcpy(buf_tmp - uc->read, buffer, pack_size + uc->read);
			void * result = get_payload_data(buf_tmp, pack_size, &payloadLen);
			if (total_size == pack_size) {
				// just one package
				lua_pushvalue(L, lua_upvalueindex(TYPE_DATA));
				lua_pushinteger(L, fd);
				//void * result = skynet_malloc(pack_size);
				//memcpy(result, buffer, size);
				lua_pushlightuserdata(L, result);
				lua_pushinteger(L, payloadLen);
				skynet_free(uc);
				return DATA_OK;
			}
			// more data
			push_data(L, fd, result, payloadLen, 0);
			buffer += pack_size + uc->read;
			size -= pack_size + uc->read;
			push_more(L, fd, buffer, size);
			lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
			skynet_free(uc);
			return DATA_MORE;
		}
		int need = uc->pack.size - uc->read;
		if (size < need) {
			memcpy((uint8_t*)uc->pack.buffer + uc->read, buffer, size);
			uc->read += size;
			insert_uncomplete(q, uc);
			return DATA_LESS;
		}
		memcpy((uint8_t*)uc->pack.buffer + uc->read, buffer, need);
		buffer += need;
		size -= need;
		void * result = get_payload_data(uc->pack.buffer, uc->pack.size, &payloadLen);
		if (size == 0) {
			lua_pushvalue(L, lua_upvalueindex(TYPE_DATA));
			lua_pushinteger(L, fd);
			lua_pushlightuserdata(L, result);
			lua_pushinteger(L, payloadLen);
			skynet_free(uc);
			return DATA_OK;
		}
		// more data
		push_data(L, fd, result, payloadLen, 0);
		skynet_free(uc);
		push_more(L, fd, buffer, size);
		lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
		return DATA_MORE;
	}
	else {
		char * data;
		char fin, Opcode, maskFlag, masks[4];
		char * payloadData;
		char temp[8];
		unsigned short usLen = 0;
		int i = 0;

		if (bufLen < 2)
		{
			struct uncomplete * uc = save_uncomplete(L, fd);
			uc->read = -size;
			memcpy(uc->header, buffer, size);
			return DATA_LESS;
		}

		fin = (buf[0] & 0x80) == 0x80; // 1bit，1表示最后一帧    
		if (!fin)
		{
			assert(0);
			return DATA_ERR;// 超过一帧暂不处理   
		}
		Opcode = (buf[0] & 0xF);
		if (0x8 == Opcode)//*  %x8 denotes a connection close
		{
			//close_uncomplete(L, message->id);
			lua_pushvalue(L, lua_upvalueindex(TYPE_CLOSE));
			lua_pushinteger(L, fd);
			//shake_handed = 0;
			//shake_handed_buf_len = 0;
			return 3;
		}
		//*%x1 denotes a text frame
		//*  %x2 denotes a binary frame
		if (1 != Opcode && 2 != Opcode){
			assert(0);
			return DATA_ERR;
		}

		maskFlag = (buf[1] & 0x80) == 0x80; // 是否包含掩码    
		if (!maskFlag)
		{
			assert(0);
			return DATA_ERR;// 不包含掩码的暂不处理  
		}

		payloadLen = buf[1] & 0x7F; // 数据长度   
		if (payloadLen == 126)
		{
			if (bufLen < 4)
			{
				struct uncomplete * uc = save_uncomplete(L, fd);
				uc->read = -size;
				memcpy(uc->header, buffer, size);
				return DATA_LESS;
			}
			payloadLen = (buf[2] & 0xFF) << 8 | (buf[3] & 0xFF);
			pack_size = 4 + sizeof(masks) + payloadLen;
		}
		else if (payloadLen == 127)
		{
			if (bufLen < HEAD_LEN_MAX)
			{
				struct uncomplete * uc = save_uncomplete(L, fd);
				uc->read = -size;
				memcpy(uc->header, buffer, size);
				return DATA_LESS;
			}
			for (i = 0; i < 8; i++)
			{
				temp[i] = buf[9 - i];
			}
			memcpy(&n, temp, 8);
			payloadLen = n;
			pack_size = HEAD_LEN_MAX + sizeof(masks) + payloadLen;
		}
		else//payloadLen < 126
		{
			pack_size = 2 + sizeof(masks) + payloadLen;
		}
		if (size < pack_size) {
			struct uncomplete * uc = save_uncomplete(L, fd);
			uc->read = size;
			uc->pack.size = pack_size;
			uc->pack.buffer = skynet_malloc(pack_size);
			memcpy(uc->pack.buffer, buffer, size);
			return DATA_LESS;
		}
		void * result = get_payload_data(buffer, pack_size, &payloadLen);
		if (size == pack_size) {
			// just one package
			lua_pushvalue(L, lua_upvalueindex(TYPE_DATA));
			lua_pushinteger(L, fd);
			//void * result = skynet_malloc(pack_size);
			//memcpy(result, buffer, size);
			lua_pushlightuserdata(L, result);
			lua_pushinteger(L, payloadLen);
			return DATA_OK;
		}
		// more data
		push_data(L, fd, result, payloadLen, 0);
		buffer += pack_size;
		size -= pack_size;
		push_more(L, fd, buffer, size);
		lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
		return DATA_MORE;
	}
}
static inline int
filter_data(lua_State *L, int fd, uint8_t * buffer, int size) {
	int ret = filter_data_(L, fd, buffer, size);
	// buffer is the data of socket message, it malloc at socket_server.c : function forward_message .
	// it should be free before return,
	skynet_free(buffer);
	return ret;
}

static void
pushstring(lua_State *L, const char * msg, int size) {
	if (msg) {
		lua_pushlstring(L, msg, size);
	}
	else {
		lua_pushliteral(L, "");
	}
}

/*
userdata queue
lightuserdata msg
integer size
return
userdata queue
string type (lua_upvalueindex(TYPE_*))
integer fd
string msg | lightuserdata/integer
*/
static int
lfilter(lua_State *L) {
	struct skynet_socket_message *message = lua_touserdata(L, 2);
	int size = luaL_checkinteger(L, 3);
	char * buffer = message->buffer;
	if (buffer == NULL) {
		buffer = (char *)(message + 1);
		size -= sizeof(*message);
	}
	else {
		size = -1;
	}

	lua_settop(L, 1);

	switch (message->type) {
	case SKYNET_SOCKET_TYPE_DATA:
		// ignore listen id (message->id)
		assert(size == -1);	// never padding string
		return filter_data(L, message->id, (uint8_t *)buffer, message->ud);
	case SKYNET_SOCKET_TYPE_CONNECT:
		// ignore listen fd connect
		return 1;
	case SKYNET_SOCKET_TYPE_CLOSE:
		// no more data in fd (message->id)
		close_uncomplete(L, message->id);
		lua_pushvalue(L, lua_upvalueindex(TYPE_CLOSE));
		lua_pushinteger(L, message->id);
		//shake_handed = 0;
		//shake_handed_buf_len = 0;
		struct queue *q = lua_touserdata(L, 1);
		remove_nn_list(q, message->id);
		return 3;
	case SKYNET_SOCKET_TYPE_ACCEPT:
		lua_pushvalue(L, lua_upvalueindex(TYPE_OPEN));
		// ignore listen id (message->id);
		lua_pushinteger(L, message->ud);
		pushstring(L, buffer, size);
		//shake_handed = 0;
		//shake_handed_buf_len = 0;
		return 4;
	case SKYNET_SOCKET_TYPE_ERROR:
		// no more data in fd (message->id)
		close_uncomplete(L, message->id);
		lua_pushvalue(L, lua_upvalueindex(TYPE_ERROR));
		lua_pushinteger(L, message->id);
		pushstring(L, buffer, size);
		return 4;
	case SKYNET_SOCKET_TYPE_WARNING:
		lua_pushvalue(L, lua_upvalueindex(TYPE_WARNING));
		lua_pushinteger(L, message->id);
		lua_pushinteger(L, message->ud);
		return 4;
	default:
		// never get here
		return 1;
	}
}

/*
userdata queue
return
integer fd
lightuserdata msg
integer size
*/
static int
lpop(lua_State *L) {
	struct queue * q = lua_touserdata(L, 1);
	if (q == NULL || q->head == q->tail)
		return 0;
	struct netpack *np = &q->queue[q->head];
	if (++q->head >= q->cap) {
		q->head = 0;
	}
	lua_pushinteger(L, np->id);
	lua_pushlightuserdata(L, np->buffer);
	lua_pushinteger(L, np->size);

	return 3;
}

/*
string msg | lightuserdata/integer

lightuserdata/integer
*/

static const char *
tolstring(lua_State *L, size_t *sz, int index) {
	const char * ptr;
	if (lua_isuserdata(L, index)) {
		ptr = (const char *)lua_touserdata(L, index);
		*sz = (size_t)luaL_checkinteger(L, index + 1);
	}
	else {
		ptr = luaL_checklstring(L, index, sz);
	}
	return ptr;
}

static inline void
write_size(uint8_t * buffer, int len) {
	buffer[0] = (len >> 8) & 0xff;
	buffer[1] = len & 0xff;
}


char *  packData(const char * message, unsigned long * len)
{
	char * data = NULL;
	unsigned long n;
	//*%x1 denotes a text frame
	//*  %x2 denotes a binary frame
	//if (1 != Opcode && 2 != Opcode){

	n = *len;
	if (n < 126)
	{
		data = (char *)skynet_malloc(n + 2);
		memset(data, 0, n + 2);
		data[0] = 0x82;//final fragment binary frame
		data[1] = n;
		memcpy(data + 2, message, n);
		*len = n + 2;
	}
	else if (n < 0xFFFF)
	{
		data = (char *)skynet_malloc(n + 4);
		memset(data, 0, n + 4);
		data[0] = 0x82;
		data[1] = 126;
		data[2] = (n >> 8 & 0xFF);
		data[3] = (n & 0xFF);
		memcpy(data + 4, message, n);
		*len = n + 4;
	}
	else
	{
		assert(0);
		// 暂不处理超长内容    
		*len = 0;
	}


	return data;
}

static int
lpack(lua_State *L) {
	size_t len;
	const char * ptr = tolstring(L, &len, 1);
	if (len >= 0x10000) {
		return luaL_error(L, "Invalid size (too long) of data : %d", (int)len);
	}

	//uint8_t * buffer = skynet_malloc(len + 2);
	//write_size(buffer, len);
	//memcpy(buffer + 2, ptr, len);
	uint8_t * buffer = (uint8_t *)packData(ptr, &len);

	lua_pushlightuserdata(L, buffer);
	lua_pushinteger(L, len);

	return 2;
}

char *  packData_client(const char * message, unsigned long * len)
{
	char * data = NULL;
	unsigned long n;
	const int  MASKING_KEY_LEN = 4;
	int i = 0;
	char masks[4] = { '1', '2', '3', '4'};
	int head_len = 0;

	n = *len;
	if (n < 126)
	{
		head_len = 2 + MASKING_KEY_LEN;
		data = (char *)skynet_malloc(n + head_len);
		memset(data, 0, n + head_len);
		data[0] = 0x82;//final fragment binary frame
		data[1] = n | 0x80;
		memcpy(data + 2, masks, sizeof(masks));
		memcpy(data + head_len, message, n);
		*len = n + head_len;

		for (i = 0; i < n; i++)
		{
			data[head_len + i] = (char)(data[head_len + i] ^ masks[i % 4]);
		}
	}
	else if (n < 0xFFFF)
	{
		head_len = 4 + MASKING_KEY_LEN;
		data = (char *)skynet_malloc(n + head_len);
		memset(data, 0, n + head_len);
		data[0] = 0x82;//final fragment binary frame
		data[1] = 126;
		data[2] = (n >> 8 & 0xFF);
		data[3] = (n & 0xFF);
		memcpy(data + 4, masks, sizeof(masks));
		memcpy(data + head_len, message, n);
		*len = n + head_len;

		for (i = 0; i < n; i++)
		{
			data[head_len + i] = (char)(data[head_len + i] ^ masks[i % 4]);
		}
	}
	else
	{
		assert(0);
		// 暂不处理超长内容    
		*len = 0;
	}


	return data;
}

static int
lpack_client(lua_State *L) {
	size_t len;
	const char * ptr = tolstring(L, &len, 1);
	if (len >= 0x10000) {
		return luaL_error(L, "Invalid size (too long) of data : %d", (int)len);
	}

	//uint8_t * buffer = skynet_malloc(len + 2);
	//write_size(buffer, len);
	//memcpy(buffer + 2, ptr, len);
	uint8_t * buffer = (uint8_t *)packData_client(ptr, &len);

	lua_pushlightuserdata(L, buffer);
	lua_pushinteger(L, len);

	return 2;
}

static int
ltostring(lua_State *L) {
	void * ptr = lua_touserdata(L, 1);
	int size = luaL_checkinteger(L, 2);
	if (ptr == NULL) {
		lua_pushliteral(L, "");
	}
	else {
		lua_pushlstring(L, (const char *)ptr, size);
		skynet_free(ptr);
	}
	return 1;
}

LUAMOD_API int
luaopen_wsnetpack(lua_State *L) {
	luaL_checkversion(L);
	luaL_Reg l[] = {
		{ "pop", lpop },
		{ "pack", lpack },
		{ "pack_client", lpack_client },
		{ "clear", lclear },
		{ "tostring", ltostring },
		{ NULL, NULL },
	};
	luaL_newlib(L, l);

	// the order is same with macros : TYPE_* (defined top)
	lua_pushliteral(L, "data");
	lua_pushliteral(L, "more");
	lua_pushliteral(L, "error");
	lua_pushliteral(L, "open");
	lua_pushliteral(L, "close");
	lua_pushliteral(L, "warning");

	lua_pushcclosure(L, lfilter, 6);
	lua_setfield(L, -2, "filter");

	//if (!pnn_hash){
	//	pnn_hash = skynet_malloc(sizeof(struct nn_hash));
	//	memset(pnn_hash, 0, sizeof(struct nn_hash));
	//}

	return 1;
}
