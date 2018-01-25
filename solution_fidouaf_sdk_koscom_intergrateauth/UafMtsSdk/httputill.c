#include <stdio.h>
#include <curl/curl.h>

static const char *PCACERTFILE = "E:\\env_common\\UAF\\koscom_it\\client\\env\\clientcert\\cacert.pem";

struct WriteThis {
	const char *readptr;
	size_t sizeleft;
};

static size_t read_callback(void *dest, size_t size, size_t nmemb, void *userp)
{
	struct WriteThis *wt = (struct WriteThis *)userp;
	size_t buffer_size = size * nmemb;

	if (wt->sizeleft) {
		/* copy as much as possible from the source to the destination */
		size_t copy_this_much = wt->sizeleft;
		if (copy_this_much > buffer_size)
			copy_this_much = buffer_size;
		memcpy(dest, wt->readptr, copy_this_much);

		wt->readptr += copy_this_much;
		wt->sizeleft -= copy_this_much;
		return copy_this_much; /* we copied this many bytes */
	}

	return 0; /* no more data left to deliver */
}

struct MemoryStruct {
	char *memory;
	size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	mem->memory = (char*)realloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory == NULL) {
		/* out of memory! */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}


void saimplehttps(char* url, char* data) {
	CURL *curl;
	CURLcode res;
	struct curl_slist *headers = NULL;
	struct MemoryStruct chunk;
	chunk.memory = (char*)malloc(1);  /* will be grown as needed by the realloc above */
	chunk.size = (size_t)0;    /* no data at this point */

	curl_global_init(CURL_GLOBAL_ALL);

	curl = curl_easy_init();

	if (!curl) {
		fprintf(stderr, "ERROR: Failed to create curl handle in fetch_session");
		return;
	}

	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json;charset=utf8");
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
	curl_easy_setopt(curl, CURLOPT_CAINFO, PCACERTFILE);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data));
	/* send all data to this function  */
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	/* we pass our 'chunk' struct to the callback function */
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(res));
	else {
		printf("%lu bytes retrieved\n", (long)chunk.size);
		printf("%s \n", chunk.memory);

	}


	curl_easy_cleanup(curl);

	free(chunk.memory);

	curl_global_cleanup();
}


int httpsPost(char *pemcert, char* url, char* data,char** outData, size_t *outDataLen) {
	int retData = 1;
	CURL *curl;
	CURLcode res;
	struct curl_slist *headers = NULL;
	struct MemoryStruct chunk;
	chunk.memory = (char*)malloc(1);  /* will be grown as needed by the realloc above */
	chunk.size = (size_t)0;    /* no data at this point */

	curl_global_init(CURL_GLOBAL_ALL);

	curl = curl_easy_init();

	if (!curl) {
		fprintf(stderr, "ERROR: Failed to create curl handle in fetch_session");
		return retData;
	}

	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json;charset=utf8");
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
	curl_easy_setopt(curl, CURLOPT_CAINFO, pemcert);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data));
	/* send all data to this function  */
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	/* we pass our 'chunk' struct to the callback function */
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(res));
	else {
		//printf("%lu bytes retrieved\n", (long)chunk.size);
		//printf("%s \n", chunk.memory);
		if (chunk.size > 0) {
			*outData = (char*)calloc(chunk.size + 1, sizeof(char));
			*outDataLen = chunk.size;
			memcpy(*outData, chunk.memory, chunk.size);
			retData = 0;
		}
	}
	
	curl_easy_cleanup(curl);

	free(chunk.memory);

	curl_global_cleanup();

	return retData;
}

void retHttpDataFree(char *data) {
	if(data)
		free(data);
}
