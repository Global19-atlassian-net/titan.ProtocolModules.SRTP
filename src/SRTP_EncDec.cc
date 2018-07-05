/******************************************************************************
* Copyright (c) 2000-2018 Ericsson Telecom AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
*
* Contributors:
* Gabor Szalai
******************************************************************************/
//
//  File:               SRTP_EncDec.cc
//  Description:        
//  Rev:                R2A
//  Prodnr:             CNL 113 769/1
//  Reference:
//
//

// include the printf macros of integer types
// The c++ standard specifies that these macros must only be defined if 
// explicitly requested.
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "SRTP_Types.hh"
#include <stdint.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <stdio.h>
#define SRTP_DEBUG(...) if(tsp__SRTP__debug__log__enabled) {log_debug(__VA_ARGS__);}

using namespace RTP__Types;

namespace SRTP__Types {

// Activate format string checking of the compiler
void log_debug(const char *fmt, ...)
  __attribute__ ((__format__ (__printf__, 1, 2)));

// Do not call directly, use SRTP_DEBUG macro
// just move the if() before call of the function
void log_debug(const char *fmt, ...) { 
  TTCN_Logger::begin_event(TTCN_DEBUG);
  TTCN_Logger::log_event("SRTP_Types: ");
  va_list args;
  va_start(args, fmt);
  TTCN_Logger::log_event_va_list(fmt, args);
  va_end(args);
  TTCN_Logger::end_event();
} 

// construct the packet index for sending, updates the ROC, and the s_l 
// or the srtcp_index
uint64_t  get_index_send(const RTP__Types::RTP__messages__union& pl__pdu,
   SRTP__crypto__context__params& pl__context){
  
  uint64_t ret_val=0;
  SRTP_DEBUG("Calculating the index of packet for encoding.")
  if(pl__pdu.ischosen(RTP__messages__union::ALT_rtp)){  // RTP packet
    // first update ROC if needed
    SRTP_DEBUG("RTP packet, current ROC %lld, s_l %lld, SEQ %d",pl__context.roc().get_long_long_val(),pl__context.s__l().get_long_long_val(),(int)pl__pdu.rtp().sequence__number())
    if(pl__context.s__l()>pl__pdu.rtp().sequence__number() ){
       // there was a roll over, update ROC and s_l
       SRTP_DEBUG("Roll over detected, updating ROC")
       ++(pl__context.roc());
       pl__context.s__l()=pl__pdu.rtp().sequence__number();
       SRTP_DEBUG("The new ROC: %lld",pl__context.roc().get_long_long_val())
    }
    pl__context.s__l()=pl__pdu.rtp().sequence__number();
    // i = 2^16 * ROC + SEQ
    ret_val=pl__context.roc().get_long_long_val();
    ret_val<<=16;
    ret_val+=pl__pdu.rtp().sequence__number();
    
  } else {
    SRTP_DEBUG("RTCP packet, current srtcp_index: %lld", pl__context.srtcp__index().get_long_long_val())
    ret_val=pl__context.srtcp__index().get_long_long_val();
//    ++pl__context.srtcp__index(); // updated after the encoding/encription
  } 
  
  return ret_val;
}


// 
OCTETSTRING prepend_os(const OCTETSTRING& oct, int len){
  int in_len=oct.lengthof();
  OCTETSTRING ret_val=oct;
  static unsigned char ch=0;
  static OCTETSTRING pad=OCTETSTRING(1,&ch);
  for(;in_len<len;in_len++){
    ret_val=pad + ret_val;
  }
  
  
  return ret_val;
}

// Generate one key based on the parameters
// See 4.3 of RFC3711
OCTETSTRING gen_key(
    uint64_t index, // the packet index
    const OCTETSTRING& key,  // the master key
    const OCTETSTRING& salt, // the salt
    int   label, // the label
    const INTEGER& kdr,  // the key derivation rate
    int   key_length // the length of the generated key in bits
  ){
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
  if(key_length==0){
    return ret_val;
  }
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Generating session key, key derivation rate:");
        kdr.log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" master key: ");
        key.log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" master salt: ");
        salt.log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" label: 0x");
        int2oct(label,1).log();
        TTCN_Logger::end_event();
      }
  uint64_t r=0;
  if(kdr>0){ // just ot avoid division by zero
    r=index % (uint64_t)(kdr.get_long_long_val());
  }
  INTEGER rr;
  rr.set_long_long_val(r);
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("r = index DIV kdr:");
        rr.log();
        TTCN_Logger::end_event();
      }  
  OCTETSTRING x=prepend_os(int2oct(label,1)+int2oct(rr,6),salt.lengthof());
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("key-id = label || r:");
        x.log();
        TTCN_Logger::end_event();
      }  
  x=x^salt;
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("x  = key_id || master salt:");
        x.log();
        TTCN_Logger::end_event();
      }  
  
  unsigned char out[16];
  AES_KEY wctx;
  AES_set_encrypt_key((const unsigned char *)key, key.lengthof()*8, &wctx);

  int key_length_octets=(key_length+7)/8;
  int key_length_blocks=(key_length_octets+15)/16;

  for(int i=0;i<key_length_blocks;i++){
    AES_encrypt((const unsigned char *)(x+int2oct(i,2)), out, &wctx);  
    ret_val=ret_val+OCTETSTRING(16,out);
  }
  ret_val=substr(ret_val,0,key_length_octets);
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("generated key:");
        ret_val.log();
        TTCN_Logger::end_event();
      }  
  return ret_val;
}

// Generate the session keys
void generate_keys(SRTP__master__key__params& key_par,uint64_t index, int n_a,int n_e, int n_s){
  key_par.srtp__session__encr__key()()=gen_key(index,
                                           key_par.master__key(),
                                           key_par.master__salt().ispresent()?key_par.master__salt()():OCTETSTRING(0,NULL),
                                           0,  // label of SRTP encr key 0x00
                                           key_par.key__derivation__rate().ispresent()?key_par.key__derivation__rate()():INTEGER(0),
                                           n_e
                                           );
  key_par.srtp__session__auth__key()()=gen_key(index,
                                           key_par.master__key(),
                                           key_par.master__salt().ispresent()?key_par.master__salt()():OCTETSTRING(0,NULL),
                                           1,  // label of SRTP auth key 0x01
                                           key_par.key__derivation__rate().ispresent()?key_par.key__derivation__rate()():INTEGER(0),
                                           n_a
                                           );
  key_par.srtp__session__salt__key()()=gen_key(index,
                                           key_par.master__key(),
                                           key_par.master__salt().ispresent()?key_par.master__salt()():OCTETSTRING(0,NULL),
                                           2,  // label of SRTP salt key 0x02
                                           key_par.key__derivation__rate().ispresent()?key_par.key__derivation__rate()():INTEGER(0),
                                           n_s
                                           );
  key_par.srtcp__session__encr__key()()=gen_key(index,
                                           key_par.master__key(),
                                           key_par.master__salt().ispresent()?key_par.master__salt()():OCTETSTRING(0,NULL),
                                           3,  // label of SRTP encr key 0x00
                                           key_par.key__derivation__rate().ispresent()?key_par.key__derivation__rate()():INTEGER(0),
                                           n_e
                                           );
  key_par.srtcp__session__auth__key()()=gen_key(index,
                                           key_par.master__key(),
                                           key_par.master__salt().ispresent()?key_par.master__salt()():OCTETSTRING(0,NULL),
                                           4,  // label of SRTP auth key 0x01
                                           key_par.key__derivation__rate().ispresent()?key_par.key__derivation__rate()():INTEGER(0),
                                           n_a
                                           );
  key_par.srtcp__session__salt__key()()=gen_key(index,
                                           key_par.master__key(),
                                           key_par.master__salt().ispresent()?key_par.master__salt()():OCTETSTRING(0,NULL),
                                           5,  // label of SRTP salt key 0x02
                                           key_par.key__derivation__rate().ispresent()?key_par.key__derivation__rate()():INTEGER(0),
                                           n_s
                                           );
}


// Retrieve the key lengths for n_a, n_e, n_s
// 0 means no key needed.
int get_n_a(const SRTP__crypto__context__params& context){
  int ret_val=0;
  switch(context.auth__param().get_selection()){
    case SRTP__auth__transform::ALT_hmac__sha1:
      if(context.auth__param().hmac__sha1().n__a().ispresent()){
        ret_val=context.auth__param().hmac__sha1().n__a()();
      } else {
        ret_val=160;  // default value in bits
      }
      break;
    case SRTP__auth__transform::ALT_rccm1:
      if(context.auth__param().rccm1().n__a().ispresent()){
        ret_val=context.auth__param().rccm1().n__a()();
      } else {
        ret_val=160;  // default value in bits
      }
      break;
    case SRTP__auth__transform::ALT_rccm2:
      if(context.auth__param().rccm2().n__a().ispresent()){
        ret_val=context.auth__param().rccm2().n__a()();
      } else {
        ret_val=160;  // default value in bits
      }
      break;
    case SRTP__auth__transform::ALT_rccm3:
      if(context.auth__param().rccm3().n__a().ispresent()){
        ret_val=context.auth__param().rccm3().n__a()();
      } else {
        ret_val=160;  // default value in bits
      }
      break;
    case SRTP__auth__transform::ALT_no__auth:
    default:
      break;
  }
  return ret_val;
}
int get_roc_r(const SRTP__crypto__context__params& context){
  int ret_val=0;
  switch(context.auth__param().get_selection()){
    case SRTP__auth__transform::ALT_hmac__sha1:
      break;
    case SRTP__auth__transform::ALT_rccm1:
        ret_val=context.auth__param().rccm1().roc__r();
      break;
    case SRTP__auth__transform::ALT_rccm2:
        ret_val=context.auth__param().rccm2().roc__r();
      break;
    case SRTP__auth__transform::ALT_rccm3:
        ret_val=context.auth__param().rccm3().roc__r();
      break;
    case SRTP__auth__transform::ALT_no__auth:
    default:
      break;
  }
  return ret_val;
}

// returns the actually n_tag, considering RCC modes and index value
int get_n_tag(const SRTP__crypto__context__params& context, bool is_rtcp,
                         uint64_t index){
  int ret_val=0;
  switch(context.auth__param().get_selection()){
    case SRTP__auth__transform::ALT_hmac__sha1:
      if(context.auth__param().hmac__sha1().n__tag().ispresent()){
        ret_val=context.auth__param().hmac__sha1().n__tag()();
      } else {
        ret_val=80;  // default value in bits
      }
      break;
    case SRTP__auth__transform::ALT_rccm1:
      if(context.auth__param().rccm1().n__tag().ispresent()){
        ret_val=context.auth__param().rccm1().n__tag()();
      } else {
        ret_val=80;  // default value in bits
      }
      if(!is_rtcp && !(index % (int)(context.auth__param().rccm1().roc__r()))){
        ret_val=0; // RTCP, RCC mode 1, index % r != 0 => no auth tag
      }
      break;
    case SRTP__auth__transform::ALT_rccm2:
      if(context.auth__param().rccm2().n__tag().ispresent()){
        ret_val=context.auth__param().rccm2().n__tag()();
      } else {
        ret_val=80;  // default value in bits
      }
      break;
    case SRTP__auth__transform::ALT_rccm3:
      if(is_rtcp){
        if(context.auth__param().rccm3().n__tag().ispresent()){
          ret_val=context.auth__param().rccm3().n__tag()();
        } else {
          ret_val=80;  // default value in bits
        }
      } else if(index % (int)(context.auth__param().rccm1().roc__r())) {
        ret_val=32; // fixed value
      } // else no auth tag
      break;
    case SRTP__auth__transform::ALT_no__auth:
    default:
      break;
  }
  return ret_val;
}
int get_n_e(const SRTP__crypto__context__params& context){
  int ret_val=0;
  switch(context.crypto__param().get_selection()){
    case SRTP__crypto__transform::ALT_aes__f8:
      if(context.crypto__param().aes__f8().n__e().ispresent()){
        ret_val=context.crypto__param().aes__f8().n__e()();
      } else {
        ret_val=128;  // default value in bits
      }
      break;
    case SRTP__crypto__transform::ALT_aes__cm:
      if(context.crypto__param().aes__cm().n__e().ispresent()){
        ret_val=context.crypto__param().aes__cm().n__e()();
      } else {
        ret_val=128;  // default value in bits
      }
      break;
    case SRTP__crypto__transform::ALT_null__transform:
    default:
      break;
  }
  return ret_val;

}
int get_n_s(const SRTP__crypto__context__params& context){
  int ret_val=0;
  switch(context.crypto__param().get_selection()){
    case SRTP__crypto__transform::ALT_aes__f8:
      if(context.crypto__param().aes__f8().n__s().ispresent()){
        ret_val=context.crypto__param().aes__f8().n__s()();
      } else {
        ret_val=112;  // default valu in bits
      }
      break;
    case SRTP__crypto__transform::ALT_aes__cm:
      if(context.crypto__param().aes__cm().n__s().ispresent()){
        ret_val=context.crypto__param().aes__cm().n__s()();
      } else {
        ret_val=112;  // default valu in bits
      }
      break;
    case SRTP__crypto__transform::ALT_null__transform:
    default:
      break;
  }
  return ret_val;

}


// search for the key based on MKI and range if defined for keys
int search_range_with_mki(uint64_t index,const SRTP__master__key__list& key_list,const OCTETSTRING& mki){
  int key_num=key_list.size_of();
  int ret_val=-1;
  for(int a=0;a<key_num;a++){
    if(key_list[a].mki__value()==mki){ // the MKI matches
      // check the range
      if(key_list[a].valid__from__to().ispresent()){
        if(key_list[a].valid__from__to()().from__value().get_long_long_val()<=(long long int)index
           && key_list[a].valid__from__to()().to__value().get_long_long_val()>=(long long int)index){
           // the range matches, we found the key
           ret_val=a;
           break; // break out from the loop
        }
        
      } else {
        //no range, we found the key
        ret_val=a;
        break; // break out from the loop
      }
    }
  }

  if(ret_val==-1){
    // No suitable key found
    TTCN_error("No suitable SRTP key found");
  }
  return ret_val;
}

// search for the key based on range if defined for keys
int search_range_without_mki(uint64_t index,const SRTP__master__key__list& key_list){
  int key_num=key_list.size_of();
  int ret_val=-1;
  for(int a=0;a<key_num;a++){
    // check the range
    if(key_list[a].valid__from__to().ispresent()){
      if(key_list[a].valid__from__to()().from__value().get_long_long_val()<=(long long int)index
         && key_list[a].valid__from__to()().to__value().get_long_long_val()>=(long long int)index){
         // the range matches, we found the key
         ret_val=a;
         break; // break out from the loop
      }

    } else {
      //no range, we found the key
      ret_val=a;
      break; // break out from the loop
    }
  }

  if(ret_val==-1){
    // No suitable key found
    TTCN_error("No suitable SRTP key found");
  }
  return ret_val;
}

// returns the index of the key in the list master_key_list
// calculate or update the keys if needed.
// For sending the everything is stored in pl_context
void get_set_update_session_keys(uint64_t index, SRTP__crypto__context__params& pl__context){
  SRTP_DEBUG("Determine the index of the key to use.")
  int key_num=pl__context.master__key__list().size_of();
  int key_index=0;
  if(key_num==0){ // No keys defined???
    TTCN_error("No keys defined for SRTP crypto context.");
  }
  
  if(pl__context.key__index()>=key_num){  // Check the key index validity
    SRTP_DEBUG("The key_index (%d) is invalid, correcting. There are only %d keys.",(int)pl__context.key__index(),key_num)
    pl__context.key__index()=0; // reset if needed.
  }

  if(key_num==1){ // if there is only one key, no need to search, just use
    SRTP_DEBUG("There is only one key. Use it unconditionally.")
    if(pl__context.mki__length()>0){ // just update the MKI if used
      pl__context.mki__value()=pl__context.master__key__list()[key_index].mki__value();
    }
  } else {  // There are several keys, choose the correct one
    SRTP_DEBUG("There are more keys, choose.")
    // if MKI is used, check it and find the correct key
    // also consider the <from,to> range
    int key_index_probe=pl__context.key__index();
    if(pl__context.mki__length()>0){
      // first check the MKI values
      // the pl__context.mki__value() holds the MKI value to use
      if(pl__context.mki__value()==pl__context.master__key__list()[key_index_probe].mki__value()){
        // The MKI matches, check the range is defined.
        if(pl__context.master__key__list()[key_index_probe].valid__from__to().ispresent()){
          // Check the range
          if(pl__context.master__key__list()[key_index_probe].valid__from__to()().from__value().get_long_long_val()<=(long long int)index
             && pl__context.master__key__list()[key_index_probe].valid__from__to()().to__value().get_long_long_val()>=(long long int)index
             ){ // range ok, we are done
            key_index=key_index_probe;
          } else { // out of range, go search
            key_index=search_range_with_mki(index,pl__context.master__key__list(),pl__context.mki__value());
            // update the used key
            pl__context.key__index()=key_index;
          }
        } else {
          // No range defined, we are done
          key_index=key_index_probe;
        }
      }
    } else {
      // no MKI, check the range if defined
      if(pl__context.master__key__list()[key_index_probe].valid__from__to().ispresent()){
        // Check the range
        if(pl__context.master__key__list()[key_index_probe].valid__from__to()().from__value().get_long_long_val()<=(long long int)index
           && pl__context.master__key__list()[key_index_probe].valid__from__to()().to__value().get_long_long_val()>=(long long int)index
           ){ // range ok, we are done
          key_index=key_index_probe;
        } else { // out of range, go search
          key_index=search_range_without_mki(index,pl__context.master__key__list());
          // update the used key
          pl__context.key__index()=key_index;
        }
      } else {
        // No range defined use the pl__context.key__index()
        key_index=pl__context.key__index();
      }
    }
  }
  SRTP_DEBUG("The selected key index is: %d",key_index)
  // Now check the keys availability and validity
  //   At least one initial key derivation SHALL be performed by SRTP, i.e.,
  //   the first key derivation is REQUIRED.  Further applications of the
  //   key derivation MAY be performed, according to the
  //   "key_derivation_rate" value in the cryptographic context.  The key
  //   derivation function SHALL initially be invoked before the first
  //   packet and then, when r > 0, a key derivation is performed whenever
  //   index mod r equals zero.  This can be thought of as "refreshing" the
  //   session keys.  The value of "key_derivation_rate" MUST be kept fixed
  //   for the lifetime of the associated master key.  
  if(!(pl__context.master__key__list()[key_index].srtp__session__encr__key().ispresent())){
    // No key generated yet. All of the keys are generated together. If one is missing all of the are missing
    SRTP_DEBUG("No keys generated yet, generate them.")
    generate_keys(pl__context.master__key__list()[key_index],index, get_n_a(pl__context),get_n_e(pl__context),get_n_s(pl__context));
  } else {
    // Check the key derivation rate presence
    
    if(pl__context.master__key__list()[key_index].key__derivation__rate().ispresent() && 
       pl__context.master__key__list()[key_index].key__derivation__rate()()>0 &&
       !(index % (pl__context.master__key__list()[key_index].key__derivation__rate()().get_long_long_val()))
    ) {
      SRTP_DEBUG("Keys are invalid. Regenerate them.")
      generate_keys(pl__context.master__key__list()[key_index],index, get_n_a(pl__context),get_n_e(pl__context),get_n_s(pl__context));
      // regeneration is needed
    } else {
      SRTP_DEBUG("Keys are valid.")
    }
  }
  pl__context.key__index()=key_index;
}

void do_aes_f8(const OCTETSTRING& iv, const OCTETSTRING& key, const OCTETSTRING& salt, OCTETSTRING& pl__packet, int header_size){
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
  int i=0;

  unsigned char mf_ch=0x55;
  OCTETSTRING m_fill=OCTETSTRING(1,&mf_ch);
  
  OCTETSTRING m=salt;
  for(i=salt.lengthof();i<key.lengthof();i++){
    m=m+m_fill;
  }
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Aes f8 parameters iv: ");
        iv.log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" key: ");
        key.log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" salt key: ");
        salt.log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" m: ");
        m.log();
        TTCN_Logger::end_event();
      }

  unsigned char out[16];
  AES_KEY wctx;
  AES_set_encrypt_key((const unsigned char *)(key^m), key.lengthof()*8, &wctx);

  AES_encrypt((const unsigned char *)(iv), out, &wctx);  

  OCTETSTRING ivp=OCTETSTRING(16,out);
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" iv': ");
        ivp.log();
        TTCN_Logger::end_event();
      }
  
  OCTETSTRING s=prepend_os(OCTETSTRING(0,NULL),16);
  AES_set_encrypt_key((const unsigned char *)(key), key.lengthof()*8, &wctx);
  
  int j=0;
  
  int num_of_whole_block=(pl__packet.lengthof()-header_size)/16;
  int last_block_size=(pl__packet.lengthof()-header_size)%16;
  
  for(i=0;i<num_of_whole_block;i++){
    SRTP_DEBUG("AES f8 j: %d ",j)
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" IV' xor S(j-1) xor  j': ");
        (ivp^s^int2oct(j,16)).log();
        TTCN_Logger::end_event();
        }
    AES_encrypt((const unsigned char *)(ivp^s^int2oct(j,16)), out, &wctx);
    s=OCTETSTRING(16,out);
    ret_val=ret_val+(substr(pl__packet,header_size+i*16,16)^s);
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" S(j)': ");
        s.log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" plaintext': ");
        substr(pl__packet,header_size+i*16,16).log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" cyphertext': ");
        (substr(pl__packet,header_size+i*16,16)^s).log();
        TTCN_Logger::end_event();
      }
    j++;
  }
  if(last_block_size){
    SRTP_DEBUG("AES f8 j: %d ",j)
    AES_encrypt((const unsigned char *)(ivp^s^int2oct(j,16)), out, &wctx);
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" IV' xor S(j-1) xor  j': ");
        (ivp^s^int2oct(j,16)).log();
        TTCN_Logger::end_event();
      }
    ret_val=ret_val+(substr(pl__packet,header_size+i*16,last_block_size)^OCTETSTRING(last_block_size,out));
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" S(j)': ");
        OCTETSTRING(last_block_size,out).log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" plaintext': ");
        substr(pl__packet,header_size+i*16,last_block_size).log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" cyphertext': ");
        (substr(pl__packet,header_size+i*16,last_block_size)^OCTETSTRING(last_block_size,out)).log();
        TTCN_Logger::end_event();
      }
  }
  pl__packet=substr(pl__packet,0,header_size)+ret_val;
  

}
void do_aes_cm(const OCTETSTRING& iv, const OCTETSTRING& key, OCTETSTRING& pl__packet, int header_size){
  int num_of_whole_block=(pl__packet.lengthof()-header_size)/16;
  int last_block_size=(pl__packet.lengthof()-header_size)%16;
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
  int i=0;
  unsigned char out[16];
  AES_KEY wctx;
  AES_set_encrypt_key((const unsigned char *)key, key.lengthof()*8, &wctx);
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Aes cm parameters iv base: ");
        iv.log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" key: ");
        key.log();
        TTCN_Logger::end_event();
      }

  for(i=0;i<num_of_whole_block;i++){
    AES_encrypt((const unsigned char *)(iv+int2oct(i,2)), out, &wctx);
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Aes counter: ");
        (iv+int2oct(i,2)).log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" keystream: ");
        OCTETSTRING(16,out).log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" input stream: ");
        substr(pl__packet,header_size+i*16,16).log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" output stream: ");
        (substr(pl__packet,header_size+i*16,16)^OCTETSTRING(16,out)).log();
        TTCN_Logger::end_event();
      }
    ret_val=ret_val+(substr(pl__packet,header_size+i*16,16)^OCTETSTRING(16,out));
  }
  if(last_block_size){
    AES_encrypt((const unsigned char *)(iv+int2oct(i,2)), out, &wctx);  
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Aes counter: ");
        (iv+int2oct(i,2)).log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" keystream: ");
        OCTETSTRING(last_block_size,out).log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" input stream: ");
        substr(pl__packet,header_size+i*16,last_block_size).log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event(" output stream: ");
        (substr(pl__packet,header_size+i*16,last_block_size)^OCTETSTRING(last_block_size,out)).log();
        TTCN_Logger::end_event();
      }
    ret_val=ret_val+(substr(pl__packet,header_size+i*16,last_block_size)^OCTETSTRING(last_block_size,out));
  }

  pl__packet=substr(pl__packet,0,header_size)+ret_val;
}

OCTETSTRING get_aes_f8_iv(const OCTETSTRING& pl__packet, const INTEGER& index_roc, bool is_rtcp){
// See the RFC3711 and the structure of the RTP/RTCP packet

      OCTETSTRING iv;
      if(is_rtcp){
        unsigned char ch=0xff;
        iv=prepend_os(bit2oct(BITSTRING(1,&ch)+int2bit(index_roc,31))+substr(pl__packet,0,8),16);
        // set the E bit also
      } else {
        iv=prepend_os(substr(pl__packet,1,11)+int2oct(index_roc,4),16);
      }
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Aes f8 iv: ");
        iv.log();
        TTCN_Logger::end_event();
      }
      return iv;
}
OCTETSTRING get_aes_cm_iv(const OCTETSTRING& pl__packet, const OCTETSTRING key ,const INTEGER& ix, bool is_rtcp){
 //where the 128-bit integer value IV SHALL be defined by the SSRC, the
//   SRTP packet index i, and the SRTP session salting key k_s, as below.
//
//     IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
// 
//  The last two octest are added by the do_aes_cm, because they are the counter, so
//
//     IV = (k_s ) XOR (SSRC * 2^48) XOR (i )
//
//   because the i is 48 bit the (SSRC * 2^48) XOR (i ) is equivalent: SSRC || i, so
//     IV = (k_s ) XOR (SSRC || i )
//  
      OCTETSTRING iv=prepend_os(key,14)^prepend_os((is_rtcp?substr(pl__packet,4,4):substr(pl__packet,8,4))+int2oct(ix,6),14);
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Aes cm iv: ");
        iv.log();
        TTCN_Logger::end_event();
      }
      return iv;
}
// Encrypts the packet according to the context parameters
void do_encryption(const RTP__Types::RTP__messages__union& pl__pdu, 
              SRTP__crypto__context__params& pl__context, OCTETSTRING& pl__packet, uint64_t index){

// first encode the packet and determine the length of the header part.
  bool is_rtcp=pl__pdu.ischosen(RTP__messages__union::ALT_rtcp);
  
  pl__packet=f__RTP__enc(pl__pdu);
  
  int header_size=0;  // in octets
  if(is_rtcp){
    header_size=8;  // fixed size, see 3.4 of RFC3711
  } else {
    if(bit2int(pl__pdu.rtp().padding__ind())){ // padding used
      header_size=pl__packet.lengthof()-(4*((pl__pdu.rtp().data().lengthof()+3)/4));  // padded to 32bit
    } else {
      header_size=pl__packet.lengthof()-pl__pdu.rtp().data().lengthof();
    }
  }
  INTEGER ix;
  ix.set_long_long_val(index);
  OCTETSTRING iv;
  // call the encryption functions
  switch(pl__context.crypto__param().get_selection()){
    case SRTP__crypto__transform::ALT_aes__f8:
// See the RFC3711 and the structure of the RTP/RTCP packet

      iv=get_aes_f8_iv(pl__packet,is_rtcp?pl__context.srtcp__index():pl__context.roc(),is_rtcp);
      do_aes_f8(iv,
      is_rtcp?pl__context.master__key__list()[pl__context.key__index()].srtcp__session__encr__key()():pl__context.master__key__list()[pl__context.key__index()].srtp__session__encr__key()(),
      is_rtcp?pl__context.master__key__list()[pl__context.key__index()].srtcp__session__salt__key()():pl__context.master__key__list()[pl__context.key__index()].srtp__session__salt__key()(),
      pl__packet,header_size);
      break;
    case SRTP__crypto__transform::ALT_aes__cm:
      iv= get_aes_cm_iv(pl__packet,
              is_rtcp?pl__context.master__key__list()[pl__context.key__index()].srtcp__session__salt__key()():pl__context.master__key__list()[pl__context.key__index()].srtp__session__salt__key()(), 
              ix,
              is_rtcp
           );

      do_aes_cm(iv,is_rtcp?pl__context.master__key__list()[pl__context.key__index()].srtcp__session__encr__key()():pl__context.master__key__list()[pl__context.key__index()].srtp__session__encr__key()(),pl__packet,header_size);
      break;
    case SRTP__crypto__transform::ALT_null__transform:
      // nothing to do.
    default:
      break;
  }

}
void do_decryption(OCTETSTRING& pl__packet,SRTP__crypto__context__params& pl__context,uint64_t index, bool is_rtcp, int header_size){
  INTEGER ix;
  ix.set_long_long_val(index);
  OCTETSTRING iv;
  switch(pl__context.crypto__param().get_selection()){
    case SRTP__crypto__transform::ALT_aes__f8:
// See the RFC3711 and the structure of the RTP/RTCP packet

      iv=get_aes_f8_iv(pl__packet,is_rtcp?ix:pl__context.roc(),is_rtcp);
      do_aes_f8(iv,
      is_rtcp?pl__context.master__key__list()[pl__context.key__index()].srtcp__session__encr__key()():pl__context.master__key__list()[pl__context.key__index()].srtp__session__encr__key()(),
      is_rtcp?pl__context.master__key__list()[pl__context.key__index()].srtcp__session__salt__key()():pl__context.master__key__list()[pl__context.key__index()].srtp__session__salt__key()(),
      pl__packet,header_size);
      break;
    case SRTP__crypto__transform::ALT_aes__cm:
      iv= get_aes_cm_iv(pl__packet,
              is_rtcp?pl__context.master__key__list()[pl__context.key__index()].srtcp__session__salt__key()():pl__context.master__key__list()[pl__context.key__index()].srtp__session__salt__key()(), 
              ix,
              is_rtcp
           );

      do_aes_cm(iv,is_rtcp?pl__context.master__key__list()[pl__context.key__index()].srtcp__session__encr__key()():pl__context.master__key__list()[pl__context.key__index()].srtp__session__encr__key()(),pl__packet,header_size);
      break;
    case SRTP__crypto__transform::ALT_null__transform:
      // nothing to do.
    default:
      break;
  }


}

// returns the authentication tag
// the MKI,auth tag,not present in the pl_packet
// the  E ,SRTCP index IS present in the pl_packet
// The ROC stored already in the pl__context
OCTETSTRING get_auth_tag(const SRTP__crypto__context__params& pl__context,
                         const OCTETSTRING pl__packet,
                         bool is_rtcp,
                         uint64_t index){
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
  SRTP_DEBUG("get_auth_tag called")
  int n_tag=get_n_tag(pl__context,is_rtcp,index)/8;
  SRTP_DEBUG("get_auth_tag, n_tag %d",n_tag)

   if(n_tag==0){
     return ret_val;
   }
// These are common in all modes.
  OCTETSTRING auth_portion;
  unsigned char res[EVP_MAX_MD_SIZE];
  const OCTETSTRING& key= is_rtcp?pl__context.master__key__list()[pl__context.key__index()].srtcp__session__auth__key()():pl__context.master__key__list()[pl__context.key__index()].srtp__session__auth__key()();
  unsigned int res_size=0;
  if(is_rtcp){
    auth_portion=pl__packet;
  } else {
    auth_portion=pl__packet+int2oct(pl__context.roc(),4);
  }
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Authenticated portion of the packet: ");
        auth_portion.log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Auth key: ");
        key.log();
        TTCN_Logger::end_event();
      }

  switch(pl__context.auth__param().get_selection()){
    case SRTP__auth__transform::ALT_hmac__sha1:{

      if(!HMAC(EVP_sha1(),(const unsigned char*)key,key.lengthof(),(const unsigned char*)auth_portion,auth_portion.lengthof(),res,&res_size)){
        TTCN_error("HMAC error");
      }
      ret_val=OCTETSTRING(n_tag,res);
      }
      break;
    case SRTP__auth__transform::ALT_rccm1:
      if(is_rtcp){
        // RCC mode 1 should not be used for RTCP, use standard HMAC_SHA1
        HMAC(EVP_sha1(),(const unsigned char*)key,key.lengthof(),(const unsigned char*)auth_portion,auth_portion.lengthof(),res,&res_size);
        ret_val=OCTETSTRING(n_tag,res);
      } else {
        if(index % (int)(pl__context.auth__param().rccm1().roc__r())){
          HMAC(EVP_sha1(),(const unsigned char*)key,key.lengthof(),(const unsigned char*)auth_portion,auth_portion.lengthof(),res,&res_size);
          ret_val=int2oct(pl__context.roc(),4)+OCTETSTRING(n_tag-4,res);
        } // else no auth tag
      }
      break;
    case SRTP__auth__transform::ALT_rccm2:
      if(is_rtcp){
        // RCC mode 2 should not be used for RTCP, use standard HMAC_SHA1
        HMAC(EVP_sha1(),(const unsigned char*)key,key.lengthof(),(const unsigned char*)auth_portion,auth_portion.lengthof(),res,&res_size);
        ret_val=OCTETSTRING(n_tag,res);
      } else {
        HMAC(EVP_sha1(),(const unsigned char*)key,key.lengthof(),(const unsigned char*)auth_portion,auth_portion.lengthof(),res,&res_size);
        if(index % (int)(pl__context.auth__param().rccm2().roc__r())){
          ret_val=int2oct(pl__context.roc(),4)+OCTETSTRING(n_tag-4,res);
        } else {
          ret_val=OCTETSTRING(n_tag,res);
        }
      }
      break;
    case SRTP__auth__transform::ALT_rccm3:
      if(is_rtcp){
        // RCC mode 3 should not be used for RTCP, use standard HMAC_SHA1
        HMAC(EVP_sha1(),(const unsigned char*)key,key.lengthof(),(const unsigned char*)auth_portion,auth_portion.lengthof(),res,&res_size);
        ret_val=OCTETSTRING(n_tag,res);
      } else {
        if(index % (int)(pl__context.auth__param().rccm3().roc__r())){
          ret_val=int2oct(pl__context.roc(),4);
        } // else no auth tag
      }
      break;
    case SRTP__auth__transform::ALT_no__auth:
    default:
      break;
  }
  
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Calculated authenticion tag: ");
        ret_val.log();
        TTCN_Logger::end_event();
      }
 
  return ret_val;

}

// The encoder follows the process described in the chapter 3.3 of RFC3711
void f__SRTP__encoder(const RTP__Types::RTP__messages__union& pl__pdu, 
              SRTP__crypto__context__params& pl__context, OCTETSTRING& pl__packet){
  SRTP_DEBUG("f_SRTP_encoder called")

  SRTP_DEBUG("f_SRTP_encoder: determine the index of the packet")
  uint64_t index=get_index_send(pl__pdu,pl__context);
  SRTP_DEBUG("f_SRTP_encoder: The index of the packet is %" PRIu64, index)
  
  get_set_update_session_keys(index,pl__context);
  SRTP_DEBUG("f_SRTP_encoder: The index of the key is %d" , (int)(pl__context.key__index()))
  
  SRTP_DEBUG("f_SRTP_encoder: ready to encrypt")
  
  do_encryption(pl__pdu,pl__context,pl__packet,index);  // and encode the packet first
  SRTP_DEBUG("f_SRTP_encoder: encryption done")

  bool is_rtcp=pl__pdu.ischosen(RTP__messages__union::ALT_rtcp);
  
  if(is_rtcp){
    // append E|SRTP index
    unsigned char ch=0xff;
    pl__packet=pl__packet+bit2oct(BITSTRING(1,&ch)+int2bit(pl__context.srtcp__index(),31));
  }
  OCTETSTRING auth=get_auth_tag(pl__context,pl__packet,is_rtcp,index);
  
  // add MKI if needed.
  if(pl__context.mki__length()>0){
    pl__packet=pl__packet+prepend_os(pl__context.master__key__list()[pl__context.key__index()].mki__value()(),pl__context.mki__length());
  }
  pl__packet=pl__packet+auth;
  
  // update processed counter
  if(is_rtcp){
    ++(pl__context.master__key__list()[pl__context.key__index()].processed__packets__srtcp());
    ++(pl__context.srtcp__index()); // updated after the encoding/encription
  } else {
    ++(pl__context.master__key__list()[pl__context.key__index()].processed__packets__srtp());
  }  
}

SRTP__result f__SRTP__decoder(const OCTETSTRING& pl__packet, 
     SRTP__crypto__context__params& pl__context, 
     RTP__Types::RTP__messages__union& pl__pdu){
  SRTP_DEBUG("f_SRTP_decoder called")

  const size_t p_length=pl__packet.lengthof();
  if(p_length<12){
    // Too short packet
    return SRTP__result::SRTP__MALFORMED__PACKET;
  }
  const unsigned char* data=(const unsigned char*)pl__packet;
// determine the packet type
  unsigned char pt=data[1];
  bool is_rtcp;
// See RFC 3550 for packet types  
  if(pt>=200 && pt<=204){
  SRTP_DEBUG("packet type : RTCP")
    is_rtcp = true;
  } else {
  SRTP_DEBUG("packet type : RTP")
    is_rtcp = false;
  }


  size_t header_size=0; // the packet header size in octets
// calculate the header size
// See RFC 3550 for header structures
  if(is_rtcp){
    // Header size is fixed.
    header_size=8;
  } else {
    header_size=12+(data[0]&0x0f)*4;
    if(data[0]&0x10){ // X bit
      if(p_length<(header_size+1)){
        // Too short packet
        return SRTP__result::SRTP__MALFORMED__PACKET;
      }
      header_size+=1+4*((data[header_size+2]<<8) + data[header_size+3]);
    }
  }
  SRTP_DEBUG("header size: %d",(int)header_size)

  if(p_length<header_size){
    // Too short packet
    return SRTP__result::SRTP__MALFORMED__PACKET;
  }

// calculate the index, See 3.3.1 and Appendix A of RFC 3711
// and MKI, auth tag length
  int mki_length=pl__context.mki__length();
  int n_tag=0;
  uint64_t index=0;
  bool e_bit=false; 
  if(is_rtcp){
    // packet index is transmitted.
    // get the auth tag length, always fixed, index is irrelevant
    n_tag=get_n_tag(pl__context, is_rtcp,0)/8;
    if(p_length<header_size+4+mki_length+(n_tag)){
      // Too short packet
      return SRTP__result::SRTP__MALFORMED__PACKET;
    }
    int srtcp_index_pos=p_length-(n_tag)-mki_length-4;
    e_bit=data[srtcp_index_pos]&0x80;
    index=(((uint64_t)(data[srtcp_index_pos]&0x7F))<<24) + (((uint64_t)(data[srtcp_index_pos+1]))<<16) +
          (((uint64_t)(data[srtcp_index_pos+2]))<<8) + (uint64_t)data[srtcp_index_pos+3];
  } else {
    int seq=(data[2]<<8) + data[3];
    n_tag=get_n_tag(pl__context, is_rtcp,seq)/8;
    if(p_length<header_size+mki_length+(n_tag)){
      // Too short packet
      return SRTP__result::SRTP__MALFORMED__PACKET;
    }

    switch(pl__context.auth__param().get_selection()){
      case SRTP__auth__transform::ALT_rccm1:   // The ROC may be signaled RFC 4771 
      case SRTP__auth__transform::ALT_rccm2:
      case SRTP__auth__transform::ALT_rccm3:
        // estimate the index with seq only. It is enough to calculate the ROC presence in the auth tag.
        // the ROC is signaled if:
        // index mod R  (ROC refresh rate)  
        // can be calculated as
        // SEQ mod R  if r < 2^16 which is true according to the RFC 4771
        if(!(seq % get_roc_r(pl__context))){
          pl__context.roc()=oct2int(OCTETSTRING(4,data+(p_length-n_tag)));
          pl__context.s__l()=seq;
          index=pl__context.roc().get_long_long_val();
          index<<=16;
          index+=seq;
          break;
        } 
        // else standard index handling, no break
      case SRTP__auth__transform::ALT_hmac__sha1:  // standard ROC & index handling
      case SRTP__auth__transform::ALT_no__auth:    // See 3.3.1 and Appendix A of RFC 3711
      default:
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("The roc: ");
        pl__context.roc().log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("The s_l: ");
        pl__context.s__l().log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("The seq: ");
        INTEGER(seq).log();
        TTCN_Logger::end_event();
      }
      if(pl__context.roc() == 0 && pl__context.s__l() == 0){ 
        // the first packet in the context.
        pl__context.s__l()=seq;
      } else {
        if(pl__context.s__l()< 32768) {  //Appendix A of RFC 3711
          if(seq> (pl__context.s__l()+32768)){
            index= (pl__context.roc().get_long_long_val()-1) & (long long)0xFFFFFFFF;  
          } else {
            index= pl__context.roc().get_long_long_val();
            if(seq>pl__context.s__l()){
              pl__context.s__l()=seq;
            }
          }
        } else {
          if(seq< (pl__context.s__l()-32768)){
            index= (pl__context.roc().get_long_long_val()+1) & (long long)0xFFFFFFFF;
            pl__context.roc().set_long_long_val(index);
            pl__context.s__l()=seq;
          } else {
            index= pl__context.roc().get_long_long_val();
            if(seq>pl__context.s__l()){
              pl__context.s__l()=seq;
            }
          }
        }
      }
        index<<=16;
        index+=seq;
        break;
      
    }
    
  }
  SRTP_DEBUG("The index of the packet is %" PRIu64, index)

  // get update the MKI if present
  if(mki_length){
    pl__context.mki__value()=OCTETSTRING(mki_length,data+(p_length-n_tag-mki_length));
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("The MKI: ");
        pl__context.mki__value().log();
        TTCN_Logger::end_event();
      }
  }

  // select and update the session keys
  get_set_update_session_keys(index,pl__context);
  SRTP_DEBUG("f_SRTP_encoder: The index of the key is %d" , (int)(pl__context.key__index()))
  
  // check the auth tag
  if(n_tag){
    OCTETSTRING auth_calculated=get_auth_tag(pl__context,OCTETSTRING(p_length-n_tag-mki_length,data),is_rtcp,index);
    if(auth_calculated != OCTETSTRING(n_tag,data+(p_length-n_tag))){
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("SRTP authentication failed.");
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Expected auth tag: ");
        auth_calculated.log();
        TTCN_Logger::end_event();
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Received auth tag: ");
        OCTETSTRING(n_tag,data+(p_length-n_tag)).log();
        TTCN_Logger::end_event();
      }
      return SRTP__result::SRTP__AUTH__FAIL;
    }
  }

  // Remove the MKI, Auth tag, SRTCP index 
  
  OCTETSTRING pure_pdu=OCTETSTRING(p_length-n_tag-mki_length-(is_rtcp?4:0),data);
      if(tsp__SRTP__debug__log__enabled) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("The packet without MKI, auth tag or SRTP index: ");
        pure_pdu.log();
        TTCN_Logger::end_event();
      }

  // Decrypt
  if(!is_rtcp || e_bit) { // If the packet is SRTCP and E bit is not set the packet is unencrypted.
    do_decryption(pure_pdu,pl__context,index, is_rtcp,header_size);
  }
  
  // Decode the result
  
  pl__pdu=f__RTP__dec(pure_pdu);
  // update processed counter
  if(is_rtcp){
    ++(pl__context.master__key__list()[pl__context.key__index()].processed__packets__srtcp());
  } else {
    ++(pl__context.master__key__list()[pl__context.key__index()].processed__packets__srtp());
  }  
  return SRTP__result::SRTP__OK;

}

}
