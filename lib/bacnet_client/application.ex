defmodule BacnetClient.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Starts a worker by calling: BacnetClient.Worker.start_link(arg)
      Hadler,
      bacnet_client()
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: BacnetClient.Supervisor]
    Supervisor.start_link(children, opts)
  end

  def bacnet_client do
    Code.ensure_loaded(Hadler)
    opt = [inet_backend: :inet, reuseport: true, reuseaddr: true, bacnet_port: 0xBAC0]

    {:ok, pid} =
     IPv4Transport.open(Hadler, opt)

    opt = [
      transport: {IPv4Transport, pid},
      segmentator: BACnet.Stack.Segmentator,
      segments_store: BACnet.Stack.SegmentsStore,
      notification_receiver: Hadler,
      name: :bacnet_client
    ]

    {BACnet.Stack.Client, opt}
  end

  require BACnet.Protocol.Constants

  def get_transport_pid do
    {_module, transport, _portal} = BACnet.Stack.Client.get_transport(:bacnet_client)
    transport
  end

  def get_tranport_bordcast_address do
    transport = get_transport_pid()
    BACnet.Stack.Transport.IPv4Transport.get_broadcast_address(transport)
  end

  def send_who_is(addr \\ {{255, 255, 255, 255}, 0xBAC0}) do
    request = %BACnet.Protocol.APDU.UnconfirmedServiceRequest{
      service: BACnet.Protocol.Constants.macro_assert_name(:unconfirmed_service_choice, :who_is),
      parameters: []
    }

    BACnet.Stack.Client.send(:bacnet_client, addr, request)
  end

  def send_who_have(addr \\ {{255, 255, 255, 255}, 0xBAC0}) do
    request = %BACnet.Protocol.APDU.UnconfirmedServiceRequest{
      service: BACnet.Protocol.Constants.macro_assert_name(:unconfirmed_service_choice, :who_has),
      parameters: []
    }

    BACnet.Stack.Client.send(:bacnet_client, addr, request)
  end



end
