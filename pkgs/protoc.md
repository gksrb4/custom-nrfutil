# protoc -o dfu-cc2.pb dfu-cc2.proto --proto_path="./" --proto_path="./proto" --python_out="./"

# python nanopb_generator.py dfu-cc2.pb

# python -m nordicsemi pkg generate --hw-version 52 --sd-req 0x0100 --application-version 1 --application ./pkgs/nrf52840_xxaa.hex --model_name "FX100" --key-file ./nordicsemi/dfu/tests/key.pem pkgs/nrf52840_test.zip

# python -m nordicsemi pkg display ./pkgs/nrf52840_test.zip