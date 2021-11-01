/*
  * Copyright (c) 2021, Net-snmp authors
  * All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted provided that the following conditions are met:
  *
  * * Redistributions of source code must retain the above copyright notice, this
  *   list of conditions and the following disclaimer.
  *
  * * Redistributions in binary form must reproduce the above copyright notice,
  *   this list of conditions and the following disclaimer in the documentation
  *   and/or other materials provided with the distribution.
  *
  * * Neither the name of the copyright holder nor the names of its
  *   contributors may be used to endorse or promote products derived from
  *   this software without specific prior written permission.
  *
  * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Declare functions.
 */
void af_gb_init(void);
void af_gb_cleanup(void);

// Simple garbage collector 
#define GB_SIZE 100

void *pointer_arr[GB_SIZE];
int pointer_idx;

// If the garbage collector is used then this must be called as first thing
// during a fuzz run.
void af_gb_init() {
  pointer_idx = 0;

   for (int i = 0; i < GB_SIZE; i++) {
     pointer_arr[i] = NULL;
   }
}

void af_gb_cleanup() {
  for(int i = 0; i < GB_SIZE; i++) {
    if (pointer_arr[i] != NULL) {
      free(pointer_arr[i]);
    }
  }
}

void *af_get_null_terminated(const uint8_t **data, size_t *size) {
#define STR_SIZE 75
  if (*size < STR_SIZE || (int)*size < 0) {
    return NULL;
  }

  void *new_s = malloc(STR_SIZE + 1);
  memcpy(new_s, *data, STR_SIZE);
  ((uint8_t *)new_s)[STR_SIZE] = '\0';

  *data = *data+STR_SIZE;
  *size -= STR_SIZE;
  return new_s;
}

void *af_gb_get_random_data(const uint8_t **data, size_t *size, size_t to_get) {
  if (*size < to_get || (int)*size < 0) {
    return NULL;
  }

  void *new_s = malloc(to_get);
  memcpy(new_s, *data, to_get);

  pointer_arr[pointer_idx++] = new_s;
  
  *data = *data + to_get;
  *size -= to_get;

  return new_s;
}

void *af_gb_get_null_terminated(const uint8_t **data, size_t *size) {

  void *nstr = af_get_null_terminated(data, size);
  if (nstr == NULL) {
    return NULL;
  }
  pointer_arr[pointer_idx++] = nstr;
  return nstr;
}

void *af_gb_alloc_data(size_t len) {
  void *ptr = calloc(1, len);
  pointer_arr[pointer_idx++] = ptr;
  
  return ptr;
}

short af_get_short(const uint8_t **data, size_t *size) {
  if (*size <= 0) return 0;
  short c = (short)(*data)[0];
  *data += 1;
  *size -= 1;
  return c;
}

int af_get_int(const uint8_t **data, size_t *size) {
  if (*size <= 4) return 0;
  const uint8_t *ptr = *data;
  int val = *((const int*)ptr);
  *data += 4;
  *size -= 4;
  return val;
}
// end simple garbage collector.
