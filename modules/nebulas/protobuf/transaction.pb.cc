// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: protobuf/transaction.proto

#include "transaction.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
extern PROTOBUF_INTERNAL_EXPORT_protobuf_2ftransaction_2eproto ::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<0> scc_info_Data_protobuf_2ftransaction_2eproto;
namespace corepb {
class DataDefaultTypeInternal {
 public:
  ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<Data> _instance;
} _Data_default_instance_;
class TransactionDefaultTypeInternal {
 public:
  ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<Transaction> _instance;
} _Transaction_default_instance_;
}  // namespace corepb
static void InitDefaultsscc_info_Data_protobuf_2ftransaction_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::corepb::_Data_default_instance_;
    new (ptr) ::corepb::Data();
    ::PROTOBUF_NAMESPACE_ID::internal::OnShutdownDestroyMessage(ptr);
  }
  ::corepb::Data::InitAsDefaultInstance();
}

::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<0> scc_info_Data_protobuf_2ftransaction_2eproto =
    {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 0, 0, InitDefaultsscc_info_Data_protobuf_2ftransaction_2eproto}, {}};

static void InitDefaultsscc_info_Transaction_protobuf_2ftransaction_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::corepb::_Transaction_default_instance_;
    new (ptr) ::corepb::Transaction();
    ::PROTOBUF_NAMESPACE_ID::internal::OnShutdownDestroyMessage(ptr);
  }
  ::corepb::Transaction::InitAsDefaultInstance();
}

::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<1> scc_info_Transaction_protobuf_2ftransaction_2eproto =
    {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 1, 0, InitDefaultsscc_info_Transaction_protobuf_2ftransaction_2eproto}, {
      &scc_info_Data_protobuf_2ftransaction_2eproto.base,}};

static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_protobuf_2ftransaction_2eproto[2];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_protobuf_2ftransaction_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_protobuf_2ftransaction_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_protobuf_2ftransaction_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::corepb::Data, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::corepb::Data, payload_type_),
  PROTOBUF_FIELD_OFFSET(::corepb::Data, payload_),
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, hash_),
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, from_),
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, to_),
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, value_),
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, nonce_),
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, timestamp_),
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, data_),
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, chain_id_),
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, gas_price_),
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, gas_limit_),
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, alg_),
  PROTOBUF_FIELD_OFFSET(::corepb::Transaction, sign_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::corepb::Data)},
  { 7, -1, sizeof(::corepb::Transaction)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::corepb::_Data_default_instance_),
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::corepb::_Transaction_default_instance_),
};

const char descriptor_table_protodef_protobuf_2ftransaction_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\032protobuf/transaction.proto\022\006corepb\"-\n\004"
  "Data\022\024\n\014payload_type\030\001 \001(\t\022\017\n\007payload\030\002 "
  "\001(\014\"\325\001\n\013Transaction\022\014\n\004hash\030\001 \001(\014\022\014\n\004fro"
  "m\030\002 \001(\014\022\n\n\002to\030\003 \001(\014\022\r\n\005value\030\004 \001(\014\022\r\n\005no"
  "nce\030\005 \001(\004\022\021\n\ttimestamp\030\006 \001(\003\022\032\n\004data\030\007 \001"
  "(\0132\014.corepb.Data\022\020\n\010chain_id\030\010 \001(\r\022\021\n\tga"
  "s_price\030\t \001(\014\022\021\n\tgas_limit\030\n \001(\014\022\013\n\003alg\030"
  "\013 \001(\r\022\014\n\004sign\030\014 \001(\014b\006proto3"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_protobuf_2ftransaction_2eproto_deps[1] = {
};
static ::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase*const descriptor_table_protobuf_2ftransaction_2eproto_sccs[2] = {
  &scc_info_Data_protobuf_2ftransaction_2eproto.base,
  &scc_info_Transaction_protobuf_2ftransaction_2eproto.base,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_protobuf_2ftransaction_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_protobuf_2ftransaction_2eproto = {
  false, false, descriptor_table_protodef_protobuf_2ftransaction_2eproto, "protobuf/transaction.proto", 307,
  &descriptor_table_protobuf_2ftransaction_2eproto_once, descriptor_table_protobuf_2ftransaction_2eproto_sccs, descriptor_table_protobuf_2ftransaction_2eproto_deps, 2, 0,
  schemas, file_default_instances, TableStruct_protobuf_2ftransaction_2eproto::offsets,
  file_level_metadata_protobuf_2ftransaction_2eproto, 2, file_level_enum_descriptors_protobuf_2ftransaction_2eproto, file_level_service_descriptors_protobuf_2ftransaction_2eproto,
};

// Force running AddDescriptors() at dynamic initialization time.
static bool dynamic_init_dummy_protobuf_2ftransaction_2eproto = (static_cast<void>(::PROTOBUF_NAMESPACE_ID::internal::AddDescriptors(&descriptor_table_protobuf_2ftransaction_2eproto)), true);
namespace corepb {

// ===================================================================

void Data::InitAsDefaultInstance() {
}
class Data::_Internal {
 public:
};

Data::Data(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:corepb.Data)
}
Data::Data(const Data& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  payload_type_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_payload_type().empty()) {
    payload_type_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_payload_type(),
      GetArena());
  }
  payload_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_payload().empty()) {
    payload_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_payload(),
      GetArena());
  }
  // @@protoc_insertion_point(copy_constructor:corepb.Data)
}

void Data::SharedCtor() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&scc_info_Data_protobuf_2ftransaction_2eproto.base);
  payload_type_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  payload_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

Data::~Data() {
  // @@protoc_insertion_point(destructor:corepb.Data)
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

void Data::SharedDtor() {
  GOOGLE_DCHECK(GetArena() == nullptr);
  payload_type_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  payload_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

void Data::ArenaDtor(void* object) {
  Data* _this = reinterpret_cast< Data* >(object);
  (void)_this;
}
void Data::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void Data::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const Data& Data::default_instance() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&::scc_info_Data_protobuf_2ftransaction_2eproto.base);
  return *internal_default_instance();
}


void Data::Clear() {
// @@protoc_insertion_point(message_clear_start:corepb.Data)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  payload_type_.ClearToEmpty(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  payload_.ClearToEmpty(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Data::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  ::PROTOBUF_NAMESPACE_ID::Arena* arena = GetArena(); (void)arena;
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    CHK_(ptr);
    switch (tag >> 3) {
      // string payload_type = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          auto str = _internal_mutable_payload_type();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(::PROTOBUF_NAMESPACE_ID::internal::VerifyUTF8(str, "corepb.Data.payload_type"));
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // bytes payload = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          auto str = _internal_mutable_payload();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag & 7) == 4 || tag == 0) {
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* Data::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:corepb.Data)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // string payload_type = 1;
  if (this->payload_type().size() > 0) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_payload_type().data(), static_cast<int>(this->_internal_payload_type().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "corepb.Data.payload_type");
    target = stream->WriteStringMaybeAliased(
        1, this->_internal_payload_type(), target);
  }

  // bytes payload = 2;
  if (this->payload().size() > 0) {
    target = stream->WriteBytesMaybeAliased(
        2, this->_internal_payload(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:corepb.Data)
  return target;
}

size_t Data::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:corepb.Data)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string payload_type = 1;
  if (this->payload_type().size() > 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_payload_type());
  }

  // bytes payload = 2;
  if (this->payload().size() > 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_payload());
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void Data::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:corepb.Data)
  GOOGLE_DCHECK_NE(&from, this);
  const Data* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<Data>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:corepb.Data)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:corepb.Data)
    MergeFrom(*source);
  }
}

void Data::MergeFrom(const Data& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:corepb.Data)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.payload_type().size() > 0) {
    _internal_set_payload_type(from._internal_payload_type());
  }
  if (from.payload().size() > 0) {
    _internal_set_payload(from._internal_payload());
  }
}

void Data::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:corepb.Data)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void Data::CopyFrom(const Data& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:corepb.Data)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Data::IsInitialized() const {
  return true;
}

void Data::InternalSwap(Data* other) {
  using std::swap;
  _internal_metadata_.Swap<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(&other->_internal_metadata_);
  payload_type_.Swap(&other->payload_type_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  payload_.Swap(&other->payload_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
}

::PROTOBUF_NAMESPACE_ID::Metadata Data::GetMetadata() const {
  return GetMetadataStatic();
}


// ===================================================================

void Transaction::InitAsDefaultInstance() {
  ::corepb::_Transaction_default_instance_._instance.get_mutable()->data_ = const_cast< ::corepb::Data*>(
      ::corepb::Data::internal_default_instance());
}
class Transaction::_Internal {
 public:
  static const ::corepb::Data& data(const Transaction* msg);
};

const ::corepb::Data&
Transaction::_Internal::data(const Transaction* msg) {
  return *msg->data_;
}
Transaction::Transaction(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:corepb.Transaction)
}
Transaction::Transaction(const Transaction& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  hash_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_hash().empty()) {
    hash_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_hash(),
      GetArena());
  }
  from_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_from().empty()) {
    from_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_from(),
      GetArena());
  }
  to_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_to().empty()) {
    to_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_to(),
      GetArena());
  }
  value_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_value().empty()) {
    value_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_value(),
      GetArena());
  }
  gas_price_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_gas_price().empty()) {
    gas_price_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_gas_price(),
      GetArena());
  }
  gas_limit_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_gas_limit().empty()) {
    gas_limit_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_gas_limit(),
      GetArena());
  }
  sign_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_sign().empty()) {
    sign_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_sign(),
      GetArena());
  }
  if (from._internal_has_data()) {
    data_ = new ::corepb::Data(*from.data_);
  } else {
    data_ = nullptr;
  }
  ::memcpy(&nonce_, &from.nonce_,
    static_cast<size_t>(reinterpret_cast<char*>(&alg_) -
    reinterpret_cast<char*>(&nonce_)) + sizeof(alg_));
  // @@protoc_insertion_point(copy_constructor:corepb.Transaction)
}

void Transaction::SharedCtor() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&scc_info_Transaction_protobuf_2ftransaction_2eproto.base);
  hash_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  from_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  to_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  value_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  gas_price_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  gas_limit_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  sign_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  ::memset(&data_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&alg_) -
      reinterpret_cast<char*>(&data_)) + sizeof(alg_));
}

Transaction::~Transaction() {
  // @@protoc_insertion_point(destructor:corepb.Transaction)
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

void Transaction::SharedDtor() {
  GOOGLE_DCHECK(GetArena() == nullptr);
  hash_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  from_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  to_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  value_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  gas_price_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  gas_limit_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  sign_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (this != internal_default_instance()) delete data_;
}

void Transaction::ArenaDtor(void* object) {
  Transaction* _this = reinterpret_cast< Transaction* >(object);
  (void)_this;
}
void Transaction::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void Transaction::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const Transaction& Transaction::default_instance() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&::scc_info_Transaction_protobuf_2ftransaction_2eproto.base);
  return *internal_default_instance();
}


void Transaction::Clear() {
// @@protoc_insertion_point(message_clear_start:corepb.Transaction)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  hash_.ClearToEmpty(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  from_.ClearToEmpty(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  to_.ClearToEmpty(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  value_.ClearToEmpty(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  gas_price_.ClearToEmpty(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  gas_limit_.ClearToEmpty(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  sign_.ClearToEmpty(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  if (GetArena() == nullptr && data_ != nullptr) {
    delete data_;
  }
  data_ = nullptr;
  ::memset(&nonce_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&alg_) -
      reinterpret_cast<char*>(&nonce_)) + sizeof(alg_));
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Transaction::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  ::PROTOBUF_NAMESPACE_ID::Arena* arena = GetArena(); (void)arena;
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    CHK_(ptr);
    switch (tag >> 3) {
      // bytes hash = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          auto str = _internal_mutable_hash();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // bytes from = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          auto str = _internal_mutable_from();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // bytes to = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 26)) {
          auto str = _internal_mutable_to();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // bytes value = 4;
      case 4:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 34)) {
          auto str = _internal_mutable_value();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // uint64 nonce = 5;
      case 5:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 40)) {
          nonce_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // int64 timestamp = 6;
      case 6:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 48)) {
          timestamp_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // .corepb.Data data = 7;
      case 7:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 58)) {
          ptr = ctx->ParseMessage(_internal_mutable_data(), ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // uint32 chain_id = 8;
      case 8:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 64)) {
          chain_id_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint32(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // bytes gas_price = 9;
      case 9:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 74)) {
          auto str = _internal_mutable_gas_price();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // bytes gas_limit = 10;
      case 10:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 82)) {
          auto str = _internal_mutable_gas_limit();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // uint32 alg = 11;
      case 11:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 88)) {
          alg_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint32(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // bytes sign = 12;
      case 12:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 98)) {
          auto str = _internal_mutable_sign();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag & 7) == 4 || tag == 0) {
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* Transaction::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:corepb.Transaction)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // bytes hash = 1;
  if (this->hash().size() > 0) {
    target = stream->WriteBytesMaybeAliased(
        1, this->_internal_hash(), target);
  }

  // bytes from = 2;
  if (this->from().size() > 0) {
    target = stream->WriteBytesMaybeAliased(
        2, this->_internal_from(), target);
  }

  // bytes to = 3;
  if (this->to().size() > 0) {
    target = stream->WriteBytesMaybeAliased(
        3, this->_internal_to(), target);
  }

  // bytes value = 4;
  if (this->value().size() > 0) {
    target = stream->WriteBytesMaybeAliased(
        4, this->_internal_value(), target);
  }

  // uint64 nonce = 5;
  if (this->nonce() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteUInt64ToArray(5, this->_internal_nonce(), target);
  }

  // int64 timestamp = 6;
  if (this->timestamp() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt64ToArray(6, this->_internal_timestamp(), target);
  }

  // .corepb.Data data = 7;
  if (this->has_data()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        7, _Internal::data(this), target, stream);
  }

  // uint32 chain_id = 8;
  if (this->chain_id() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteUInt32ToArray(8, this->_internal_chain_id(), target);
  }

  // bytes gas_price = 9;
  if (this->gas_price().size() > 0) {
    target = stream->WriteBytesMaybeAliased(
        9, this->_internal_gas_price(), target);
  }

  // bytes gas_limit = 10;
  if (this->gas_limit().size() > 0) {
    target = stream->WriteBytesMaybeAliased(
        10, this->_internal_gas_limit(), target);
  }

  // uint32 alg = 11;
  if (this->alg() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteUInt32ToArray(11, this->_internal_alg(), target);
  }

  // bytes sign = 12;
  if (this->sign().size() > 0) {
    target = stream->WriteBytesMaybeAliased(
        12, this->_internal_sign(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:corepb.Transaction)
  return target;
}

size_t Transaction::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:corepb.Transaction)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // bytes hash = 1;
  if (this->hash().size() > 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_hash());
  }

  // bytes from = 2;
  if (this->from().size() > 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_from());
  }

  // bytes to = 3;
  if (this->to().size() > 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_to());
  }

  // bytes value = 4;
  if (this->value().size() > 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_value());
  }

  // bytes gas_price = 9;
  if (this->gas_price().size() > 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_gas_price());
  }

  // bytes gas_limit = 10;
  if (this->gas_limit().size() > 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_gas_limit());
  }

  // bytes sign = 12;
  if (this->sign().size() > 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_sign());
  }

  // .corepb.Data data = 7;
  if (this->has_data()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *data_);
  }

  // uint64 nonce = 5;
  if (this->nonce() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::UInt64Size(
        this->_internal_nonce());
  }

  // int64 timestamp = 6;
  if (this->timestamp() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int64Size(
        this->_internal_timestamp());
  }

  // uint32 chain_id = 8;
  if (this->chain_id() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::UInt32Size(
        this->_internal_chain_id());
  }

  // uint32 alg = 11;
  if (this->alg() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::UInt32Size(
        this->_internal_alg());
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void Transaction::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:corepb.Transaction)
  GOOGLE_DCHECK_NE(&from, this);
  const Transaction* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<Transaction>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:corepb.Transaction)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:corepb.Transaction)
    MergeFrom(*source);
  }
}

void Transaction::MergeFrom(const Transaction& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:corepb.Transaction)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.hash().size() > 0) {
    _internal_set_hash(from._internal_hash());
  }
  if (from.from().size() > 0) {
    _internal_set_from(from._internal_from());
  }
  if (from.to().size() > 0) {
    _internal_set_to(from._internal_to());
  }
  if (from.value().size() > 0) {
    _internal_set_value(from._internal_value());
  }
  if (from.gas_price().size() > 0) {
    _internal_set_gas_price(from._internal_gas_price());
  }
  if (from.gas_limit().size() > 0) {
    _internal_set_gas_limit(from._internal_gas_limit());
  }
  if (from.sign().size() > 0) {
    _internal_set_sign(from._internal_sign());
  }
  if (from.has_data()) {
    _internal_mutable_data()->::corepb::Data::MergeFrom(from._internal_data());
  }
  if (from.nonce() != 0) {
    _internal_set_nonce(from._internal_nonce());
  }
  if (from.timestamp() != 0) {
    _internal_set_timestamp(from._internal_timestamp());
  }
  if (from.chain_id() != 0) {
    _internal_set_chain_id(from._internal_chain_id());
  }
  if (from.alg() != 0) {
    _internal_set_alg(from._internal_alg());
  }
}

void Transaction::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:corepb.Transaction)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void Transaction::CopyFrom(const Transaction& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:corepb.Transaction)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Transaction::IsInitialized() const {
  return true;
}

void Transaction::InternalSwap(Transaction* other) {
  using std::swap;
  _internal_metadata_.Swap<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(&other->_internal_metadata_);
  hash_.Swap(&other->hash_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  from_.Swap(&other->from_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  to_.Swap(&other->to_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  value_.Swap(&other->value_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  gas_price_.Swap(&other->gas_price_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  gas_limit_.Swap(&other->gas_limit_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  sign_.Swap(&other->sign_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  ::PROTOBUF_NAMESPACE_ID::internal::memswap<
      PROTOBUF_FIELD_OFFSET(Transaction, alg_)
      + sizeof(Transaction::alg_)
      - PROTOBUF_FIELD_OFFSET(Transaction, data_)>(
          reinterpret_cast<char*>(&data_),
          reinterpret_cast<char*>(&other->data_));
}

::PROTOBUF_NAMESPACE_ID::Metadata Transaction::GetMetadata() const {
  return GetMetadataStatic();
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace corepb
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::corepb::Data* Arena::CreateMaybeMessage< ::corepb::Data >(Arena* arena) {
  return Arena::CreateMessageInternal< ::corepb::Data >(arena);
}
template<> PROTOBUF_NOINLINE ::corepb::Transaction* Arena::CreateMaybeMessage< ::corepb::Transaction >(Arena* arena) {
  return Arena::CreateMessageInternal< ::corepb::Transaction >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>