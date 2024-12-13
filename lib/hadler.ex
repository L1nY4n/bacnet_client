defmodule Hadler do
  alias BACnet.Stack.TrendLogger.Log
  alias BACnet.Protocol.APDU.UnconfirmedServiceRequest
  alias BACnet.Protocol.Constants
  alias BACnet.Protocol.Services.ReadPropertyMultiple
  alias BACnet.Protocol.AccessSpecification
  alias BACnet.Protocol.ObjectIdentifier
  use GenServer

  require Logger

  def start_link(init_arg) do
    GenServer.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  def init(init_arg) do
    state = %{
      invoke_id: 0
    }

    {:ok, state}
  end

  def handle_info(
        {:bacnet_transport, _proto, source_address, {:apdu, bvlc, npci, raw_apdu} = cb_data,
         portal} = msg,
        state
      ) do
    {:ok, apdu} = BACnet.Protocol.APDU.decode(raw_apdu)

    Logger.info(
      "Got message---: source_address: #{inspect(source_address)} bvlc: #{inspect(bvlc)}, npci: #{inspect(npci)}, apdu: #{inspect(apdu)}"
    )

    case apdu do
      %UnconfirmedServiceRequest{} = s ->
        case UnconfirmedServiceRequest.to_service(s) do
          {:ok, s} ->
            Logger.info(" serveice: #{inspect(s)}")
            handle_service(s, source_address, state)

          {:error, err} ->
            Logger.info("Error: #{inspect(err)}")
        end

      %BACnet.Protocol.APDU.ComplexACK{} = ack ->
        Logger.info("ACK: #{inspect(ack)}")
        send(GenServer.whereis(:bacnet_client), msg)
    end

    {:noreply, state}
  end

  def handle_service(s, addr, %{invoke_id: invoke_id}) do
    case s do
      %BACnet.Protocol.Services.IAm{device: device, vendor_id: vendor} ->
        case device do
          %BACnet.Protocol.ObjectIdentifier{type: :device, instance: instance} ->
            Logger.info("IAm device: #{inspect(instance)} vendor: #{inspect(vendor)}")

            read_property = %BACnet.Protocol.Services.ReadProperty{
              object_identifier: %BACnet.Protocol.ObjectIdentifier{
                type: :device,
                instance: instance
              },
              property_identifier: 76,
              property_array_index: nil
            }

            {:ok, request} =
              BACnet.Protocol.Services.ReadProperty.to_apdu(read_property, invoke_id: invoke_id)

            Logger.info("ReadProperty: #{inspect(request)}")

            Task.start(fn ->
              res = BACnet.Stack.Client.send(:bacnet_client, addr, request)
              {:ok, _} = res
            end)

          _ ->
            nil
        end

        BacnetClient.Application.send_who_have()

      unknown_service ->
        Logger.info("Unknown service: #{inspect(unknown_service)}")
    end
  end

  def handle_msg(a, b, c) do
    Logger.debug("Got message: #{inspect({a, b, c})}")

    # 22:44:34.967 [info] Got message: {{{192, 168, 60, 40}, 47808}, {:apdu, :original_unicast, %BACnet.Protocol.NPCI{priority: :normal, expects_reply: false, destination: nil, source: nil, hopcount: nil, is_network_message: false}, <<16, 0, 196, 2, 0, 0, 99, 34, 1, 224, 145, 0, 33, 36>>}, #Port<0.9>}
    #     BACnet.Protocol.APDU.decode <<16, 0, 196, 2, 0, 0, 99, 34, 1, 224, 145, 0, 33, 36>>
    # {:ok,
    #  %BACnet.Protocol.APDU.UnconfirmedServiceRequest{
    #    service: :i_am,
    #    parameters: [
    #      object_identifier: %BACnet.Protocol.ObjectIdentifier{
    #        type: :device,
    #        instance: 99
    #      },
    #      unsigned_integer: 480,
    #      enumerated: 0,
    #      unsigned_integer: 36
    #    ]
    #  }}
  end

  def send_read_property(addr, object_id, invoke_id) do
    read_property = %BACnet.Protocol.Services.ReadProperty{
      object_identifier: %BACnet.Protocol.ObjectIdentifier{
        type: :device,
        instance: object_id
      },
      property_identifier: 76,
      property_array_index: nil
    }

    {:ok, request} =
      BACnet.Protocol.Services.ReadProperty.to_apdu(read_property, invoke_id: invoke_id)

    with {:ok, ack} <- BACnet.Stack.Client.send(:bacnet_client, addr, request) do
      BACnet.Protocol.Services.Ack.ReadPropertyAck.from_apdu(ack)
    else
      err ->
        err
    end
  end

  def read_multiple_properties(addr, object_id, invoke_id) do
    read_property = %BACnet.Protocol.Services.ReadPropertyMultiple{
      list: [
        %AccessSpecification{
          object_identifier: %ObjectIdentifier{
            type: :analog_input,
            instance: 0
          },
          properties: [
            %AccessSpecification.Property{
              property_identifier: :present_value,
              property_array_index: nil,
              property_value: nil
            }
          ]
        },
        %AccessSpecification{
          object_identifier: %ObjectIdentifier{
            type: :analog_input,
            instance: 2
          },
          properties: [
            :all
          ]
        }
      ]
    }

    {:ok, request} =
      BACnet.Protocol.Services.ReadPropertyMultiple.to_apdu(read_property, invoke_id: invoke_id)

    BACnet.Stack.Client.send(:bacnet_client, addr, request)
  end
end
