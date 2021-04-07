# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: dfu-cc2.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from nordicsemi.dfu import nanopb_pb2 as nanopb__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='dfu-cc2.proto',
  package='dfu',
  syntax='proto2',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\rdfu-cc2.proto\x12\x03\x64\x66u\x1a\x0cnanopb.proto\"6\n\x04Hash\x12 \n\thash_type\x18\x01 \x02(\x0e\x32\r.dfu.HashType\x12\x0c\n\x04hash\x18\x02 \x02(\x0c\"B\n\x0e\x42ootValidation\x12!\n\x04type\x18\x01 \x02(\x0e\x32\x13.dfu.ValidationType\x12\r\n\x05\x62ytes\x18\x02 \x02(\x0c\"\x93\x02\n\x0bInitCommand\x12\x12\n\nfw_version\x18\x01 \x01(\r\x12\x12\n\nhw_version\x18\x02 \x01(\r\x12\x12\n\x06sd_req\x18\x03 \x03(\rB\x02\x10\x01\x12\x19\n\x04type\x18\x04 \x01(\x0e\x32\x0b.dfu.FwType\x12\x0f\n\x07sd_size\x18\x05 \x01(\r\x12\x0f\n\x07\x62l_size\x18\x06 \x01(\r\x12\x10\n\x08\x61pp_size\x18\x07 \x01(\r\x12\x17\n\x04hash\x18\x08 \x01(\x0b\x32\t.dfu.Hash\x12\x17\n\x08is_debug\x18\t \x01(\x08:\x05\x66\x61lse\x12,\n\x0f\x62oot_validation\x18\n \x03(\x0b\x32\x13.dfu.BootValidation\x12\x19\n\nmodel_name\x18\x0b \x02(\tB\x05\x92?\x02\x08\x10\"\x1f\n\x0cResetCommand\x12\x0f\n\x07timeout\x18\x01 \x02(\r\"i\n\x07\x43ommand\x12\x1c\n\x07op_code\x18\x01 \x01(\x0e\x32\x0b.dfu.OpCode\x12\x1e\n\x04init\x18\x02 \x01(\x0b\x32\x10.dfu.InitCommand\x12 \n\x05reset\x18\x03 \x01(\x0b\x32\x11.dfu.ResetCommand\"m\n\rSignedCommand\x12\x1d\n\x07\x63ommand\x18\x01 \x02(\x0b\x32\x0c.dfu.Command\x12*\n\x0esignature_type\x18\x02 \x02(\x0e\x32\x12.dfu.SignatureType\x12\x11\n\tsignature\x18\x03 \x02(\x0c\"S\n\x06Packet\x12\x1d\n\x07\x63ommand\x18\x01 \x01(\x0b\x32\x0c.dfu.Command\x12*\n\x0esigned_command\x18\x02 \x01(\x0b\x32\x12.dfu.SignedCommand*\x1d\n\x06OpCode\x12\t\n\x05RESET\x10\x00\x12\x08\n\x04INIT\x10\x01*n\n\x06\x46wType\x12\x0f\n\x0b\x41PPLICATION\x10\x00\x12\x0e\n\nSOFTDEVICE\x10\x01\x12\x0e\n\nBOOTLOADER\x10\x02\x12\x19\n\x15SOFTDEVICE_BOOTLOADER\x10\x03\x12\x18\n\x14\x45XTERNAL_APPLICATION\x10\x04*D\n\x08HashType\x12\x0b\n\x07NO_HASH\x10\x00\x12\x07\n\x03\x43RC\x10\x01\x12\n\n\x06SHA128\x10\x02\x12\n\n\x06SHA256\x10\x03\x12\n\n\x06SHA512\x10\x04*t\n\x0eValidationType\x12\x11\n\rNO_VALIDATION\x10\x00\x12\x1a\n\x16VALIDATE_GENERATED_CRC\x10\x01\x12\x13\n\x0fVALIDATE_SHA256\x10\x02\x12\x1e\n\x1aVALIDATE_ECDSA_P256_SHA256\x10\x03*3\n\rSignatureType\x12\x15\n\x11\x45\x43\x44SA_P256_SHA256\x10\x00\x12\x0b\n\x07\x45\x44\x32\x35\x35\x31\x39\x10\x01'
  ,
  dependencies=[nanopb__pb2.DESCRIPTOR,])

_OPCODE = _descriptor.EnumDescriptor(
  name='OpCode',
  full_name='dfu.OpCode',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='RESET', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='INIT', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=774,
  serialized_end=803,
)
_sym_db.RegisterEnumDescriptor(_OPCODE)

OpCode = enum_type_wrapper.EnumTypeWrapper(_OPCODE)
_FWTYPE = _descriptor.EnumDescriptor(
  name='FwType',
  full_name='dfu.FwType',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='APPLICATION', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SOFTDEVICE', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='BOOTLOADER', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SOFTDEVICE_BOOTLOADER', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='EXTERNAL_APPLICATION', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=805,
  serialized_end=915,
)
_sym_db.RegisterEnumDescriptor(_FWTYPE)

FwType = enum_type_wrapper.EnumTypeWrapper(_FWTYPE)
_HASHTYPE = _descriptor.EnumDescriptor(
  name='HashType',
  full_name='dfu.HashType',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NO_HASH', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='CRC', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SHA128', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SHA256', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SHA512', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=917,
  serialized_end=985,
)
_sym_db.RegisterEnumDescriptor(_HASHTYPE)

HashType = enum_type_wrapper.EnumTypeWrapper(_HASHTYPE)
_VALIDATIONTYPE = _descriptor.EnumDescriptor(
  name='ValidationType',
  full_name='dfu.ValidationType',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NO_VALIDATION', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='VALIDATE_GENERATED_CRC', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='VALIDATE_SHA256', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='VALIDATE_ECDSA_P256_SHA256', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=987,
  serialized_end=1103,
)
_sym_db.RegisterEnumDescriptor(_VALIDATIONTYPE)

ValidationType = enum_type_wrapper.EnumTypeWrapper(_VALIDATIONTYPE)
_SIGNATURETYPE = _descriptor.EnumDescriptor(
  name='SignatureType',
  full_name='dfu.SignatureType',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='ECDSA_P256_SHA256', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='ED25519', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=1105,
  serialized_end=1156,
)
_sym_db.RegisterEnumDescriptor(_SIGNATURETYPE)

SignatureType = enum_type_wrapper.EnumTypeWrapper(_SIGNATURETYPE)
RESET = 0
INIT = 1
APPLICATION = 0
SOFTDEVICE = 1
BOOTLOADER = 2
SOFTDEVICE_BOOTLOADER = 3
EXTERNAL_APPLICATION = 4
NO_HASH = 0
CRC = 1
SHA128 = 2
SHA256 = 3
SHA512 = 4
NO_VALIDATION = 0
VALIDATE_GENERATED_CRC = 1
VALIDATE_SHA256 = 2
VALIDATE_ECDSA_P256_SHA256 = 3
ECDSA_P256_SHA256 = 0
ED25519 = 1



_HASH = _descriptor.Descriptor(
  name='Hash',
  full_name='dfu.Hash',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='hash_type', full_name='dfu.Hash.hash_type', index=0,
      number=1, type=14, cpp_type=8, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='hash', full_name='dfu.Hash.hash', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=36,
  serialized_end=90,
)


_BOOTVALIDATION = _descriptor.Descriptor(
  name='BootValidation',
  full_name='dfu.BootValidation',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='dfu.BootValidation.type', index=0,
      number=1, type=14, cpp_type=8, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='bytes', full_name='dfu.BootValidation.bytes', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=92,
  serialized_end=158,
)


_INITCOMMAND = _descriptor.Descriptor(
  name='InitCommand',
  full_name='dfu.InitCommand',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='fw_version', full_name='dfu.InitCommand.fw_version', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='hw_version', full_name='dfu.InitCommand.hw_version', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='sd_req', full_name='dfu.InitCommand.sd_req', index=2,
      number=3, type=13, cpp_type=3, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=b'\020\001', file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='type', full_name='dfu.InitCommand.type', index=3,
      number=4, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='sd_size', full_name='dfu.InitCommand.sd_size', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='bl_size', full_name='dfu.InitCommand.bl_size', index=5,
      number=6, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='app_size', full_name='dfu.InitCommand.app_size', index=6,
      number=7, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='hash', full_name='dfu.InitCommand.hash', index=7,
      number=8, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='is_debug', full_name='dfu.InitCommand.is_debug', index=8,
      number=9, type=8, cpp_type=7, label=1,
      has_default_value=True, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='boot_validation', full_name='dfu.InitCommand.boot_validation', index=9,
      number=10, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='model_name', full_name='dfu.InitCommand.model_name', index=10,
      number=11, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=b'\222?\002\010\020', file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=161,
  serialized_end=436,
)


_RESETCOMMAND = _descriptor.Descriptor(
  name='ResetCommand',
  full_name='dfu.ResetCommand',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='timeout', full_name='dfu.ResetCommand.timeout', index=0,
      number=1, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=438,
  serialized_end=469,
)


_COMMAND = _descriptor.Descriptor(
  name='Command',
  full_name='dfu.Command',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='op_code', full_name='dfu.Command.op_code', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='init', full_name='dfu.Command.init', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='reset', full_name='dfu.Command.reset', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=471,
  serialized_end=576,
)


_SIGNEDCOMMAND = _descriptor.Descriptor(
  name='SignedCommand',
  full_name='dfu.SignedCommand',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='command', full_name='dfu.SignedCommand.command', index=0,
      number=1, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='signature_type', full_name='dfu.SignedCommand.signature_type', index=1,
      number=2, type=14, cpp_type=8, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='signature', full_name='dfu.SignedCommand.signature', index=2,
      number=3, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=578,
  serialized_end=687,
)


_PACKET = _descriptor.Descriptor(
  name='Packet',
  full_name='dfu.Packet',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='command', full_name='dfu.Packet.command', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='signed_command', full_name='dfu.Packet.signed_command', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=689,
  serialized_end=772,
)

_HASH.fields_by_name['hash_type'].enum_type = _HASHTYPE
_BOOTVALIDATION.fields_by_name['type'].enum_type = _VALIDATIONTYPE
_INITCOMMAND.fields_by_name['type'].enum_type = _FWTYPE
_INITCOMMAND.fields_by_name['hash'].message_type = _HASH
_INITCOMMAND.fields_by_name['boot_validation'].message_type = _BOOTVALIDATION
_COMMAND.fields_by_name['op_code'].enum_type = _OPCODE
_COMMAND.fields_by_name['init'].message_type = _INITCOMMAND
_COMMAND.fields_by_name['reset'].message_type = _RESETCOMMAND
_SIGNEDCOMMAND.fields_by_name['command'].message_type = _COMMAND
_SIGNEDCOMMAND.fields_by_name['signature_type'].enum_type = _SIGNATURETYPE
_PACKET.fields_by_name['command'].message_type = _COMMAND
_PACKET.fields_by_name['signed_command'].message_type = _SIGNEDCOMMAND
DESCRIPTOR.message_types_by_name['Hash'] = _HASH
DESCRIPTOR.message_types_by_name['BootValidation'] = _BOOTVALIDATION
DESCRIPTOR.message_types_by_name['InitCommand'] = _INITCOMMAND
DESCRIPTOR.message_types_by_name['ResetCommand'] = _RESETCOMMAND
DESCRIPTOR.message_types_by_name['Command'] = _COMMAND
DESCRIPTOR.message_types_by_name['SignedCommand'] = _SIGNEDCOMMAND
DESCRIPTOR.message_types_by_name['Packet'] = _PACKET
DESCRIPTOR.enum_types_by_name['OpCode'] = _OPCODE
DESCRIPTOR.enum_types_by_name['FwType'] = _FWTYPE
DESCRIPTOR.enum_types_by_name['HashType'] = _HASHTYPE
DESCRIPTOR.enum_types_by_name['ValidationType'] = _VALIDATIONTYPE
DESCRIPTOR.enum_types_by_name['SignatureType'] = _SIGNATURETYPE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Hash = _reflection.GeneratedProtocolMessageType('Hash', (_message.Message,), {
  'DESCRIPTOR' : _HASH,
  '__module__' : 'dfu_cc2_pb2'
  # @@protoc_insertion_point(class_scope:dfu.Hash)
  })
_sym_db.RegisterMessage(Hash)

BootValidation = _reflection.GeneratedProtocolMessageType('BootValidation', (_message.Message,), {
  'DESCRIPTOR' : _BOOTVALIDATION,
  '__module__' : 'dfu_cc2_pb2'
  # @@protoc_insertion_point(class_scope:dfu.BootValidation)
  })
_sym_db.RegisterMessage(BootValidation)

InitCommand = _reflection.GeneratedProtocolMessageType('InitCommand', (_message.Message,), {
  'DESCRIPTOR' : _INITCOMMAND,
  '__module__' : 'dfu_cc2_pb2'
  # @@protoc_insertion_point(class_scope:dfu.InitCommand)
  })
_sym_db.RegisterMessage(InitCommand)

ResetCommand = _reflection.GeneratedProtocolMessageType('ResetCommand', (_message.Message,), {
  'DESCRIPTOR' : _RESETCOMMAND,
  '__module__' : 'dfu_cc2_pb2'
  # @@protoc_insertion_point(class_scope:dfu.ResetCommand)
  })
_sym_db.RegisterMessage(ResetCommand)

Command = _reflection.GeneratedProtocolMessageType('Command', (_message.Message,), {
  'DESCRIPTOR' : _COMMAND,
  '__module__' : 'dfu_cc2_pb2'
  # @@protoc_insertion_point(class_scope:dfu.Command)
  })
_sym_db.RegisterMessage(Command)

SignedCommand = _reflection.GeneratedProtocolMessageType('SignedCommand', (_message.Message,), {
  'DESCRIPTOR' : _SIGNEDCOMMAND,
  '__module__' : 'dfu_cc2_pb2'
  # @@protoc_insertion_point(class_scope:dfu.SignedCommand)
  })
_sym_db.RegisterMessage(SignedCommand)

Packet = _reflection.GeneratedProtocolMessageType('Packet', (_message.Message,), {
  'DESCRIPTOR' : _PACKET,
  '__module__' : 'dfu_cc2_pb2'
  # @@protoc_insertion_point(class_scope:dfu.Packet)
  })
_sym_db.RegisterMessage(Packet)


_INITCOMMAND.fields_by_name['sd_req']._options = None
_INITCOMMAND.fields_by_name['model_name']._options = None
# @@protoc_insertion_point(module_scope)
