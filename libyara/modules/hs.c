/*
Copyright (c) 2018. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <yara/modules.h>

#include <hs.h>

#define MODULE_NAME hs

int hs_match_handler(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *ctx)
{
  *(int *)ctx = 1;
  return 0;
}

define_function(hs_match)
{
  YR_SCAN_CONTEXT* context = scan_context();
  SIZED_STRING* pattern = sized_string_argument(1);

  hs_database_t* database;
  hs_compile_error_t* compile_err;
  if (hs_compile(pattern->c_string, HS_FLAG_DOTALL, HS_MODE_STREAM, NULL, &database, &compile_err) != HS_SUCCESS)
  {
    fprintf(stderr, "ERROR: Unable to compile pattern: \"%s\": %s\n", pattern->c_string, compile_err->message);
    hs_free_compile_error(compile_err);
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  hs_scratch_t *scratch;
  if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS)
  {
    fprintf(stderr, "ERROR: Unable to allocate scratch space.\n");
    hs_free_database(database);
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  hs_stream_t *stream = NULL;
  if (hs_open_stream(database, 0, &stream) != HS_SUCCESS)
  {
    fprintf(stderr, "ERROR: Unable to open stream.\n");
    hs_free_scratch(scratch);
    hs_free_database(database);
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  hs_error_t err = HS_SUCCESS;
  int result = 0;

  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;
  foreach_memory_block(iterator, block)
  {
    const uint8_t* block_data = block->fetch_data(block);
    if (block_data == NULL)
      break;

    err = hs_scan_stream(stream, (char *)block_data, block->size, 0, scratch, hs_match_handler, &result);
    if (err != HS_SUCCESS)
        break;
  }

  if (err == HS_SUCCESS)
    err = hs_close_stream(stream, scratch, hs_match_handler, &result);

  hs_free_scratch(scratch);
  hs_free_database(database);

  if (err != HS_SUCCESS)
  {
    fprintf(stderr, "ERROR: Unable to scan block.\n");
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  return_integer(result);
}

begin_declarations;

  declare_function("match", "s", "i", hs_match);

end_declarations;


int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
