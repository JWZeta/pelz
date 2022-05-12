#include "charbuf.h"
#include "pelz_request_handler.h"
#include "common_table.h"
#include "aes_keywrap_3394nopad.h"

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

RequestResponseStatus pelz_request_handler(RequestType request_type, charbuf key_id_in, charbuf data_in, int socket_id, charbuf * output)
{
  charbuf outData;
  charbuf key_id;
  charbuf data;
  int index;

  //get_decrypted_key_id(key_id, &decrypted_key_id);
  if (socket_id >= 0)
  {
    //get_decrypted_value(key_id_in, &key_id, socket_id);
    key_id = copy_chars_from_charbuf(key_id_in, 0); //Remove
  }
  else
  {
    key_id = copy_chars_from_charbuf(key_id_in, 0);
  }

  if (table_lookup(KEY, key_id, &index))
  {
    free_charbuf(&key_id);
    return KEK_NOT_LOADED;
  }
  free_charbuf(&key_id);

  if(socket_id >= 0)
  {
    //get_decrypted_value(data_in, &data, socket_id);
    data = copy_chars_from_charbuf(data_in, 0); //Remove
  }
  else
  {
    data = copy_chars_from_charbuf(data_in, 0);
  }

  //Encrypt or Decrypt data per request_type
  switch (request_type)
  {
  case REQ_ENC:
    if ((key_table.entries[index].value.key.len < 16 || key_table.entries[index].value.key.len % 8 != 0) || (data.len < 16
        || data.len % 8 != 0))
    {
      secure_free_charbuf(&data);
      return KEY_OR_DATA_ERROR;
    }
    if (aes_keywrap_3394nopad_encrypt(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len,
        data.chars, data.len, &outData.chars, &outData.len))
    {
      secure_free_charbuf(&data);
      return ENCRYPT_ERROR;
    }
    break;
  case REQ_DEC:
    if ((key_table.entries[index].value.key.len < 16 || key_table.entries[index].value.key.len % 8 != 0) || (data.len < 24
        || data.len % 8 != 0))
    {
      secure_free_charbuf(&data);
      return KEY_OR_DATA_ERROR;
    }
    if (aes_keywrap_3394nopad_decrypt(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len,
        data.chars, data.len, &outData.chars, &outData.len))
    {
      secure_free_charbuf(&data);
      return DECRYPT_ERROR;
    }
    break;
  default:
    secure_free_charbuf(&data);
    return REQUEST_TYPE_ERROR;
  }
  secure_free_charbuf(&data);

  if (socket_id >= 0)
  {
    //get_encrypted_value(outData, &output, socket_id);
    output->len = outData.len; //Remove
    ocall_malloc(output->len, &output->chars); //Keep
    memcpy(output->chars, outData.chars, output->len); //Remove
  }
  else
  {
    output->len = outData.len;
    ocall_malloc(output->len, &output->chars);
    memcpy(output->chars, outData.chars, output->len);
  }
  return REQUEST_OK;
}
