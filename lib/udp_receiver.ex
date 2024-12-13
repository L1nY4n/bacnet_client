defmodule UdpReceiver do
  use GenServer

  # 启动 UDP 服务
  def start_link(port) do
    GenServer.start_link(__MODULE__, port, name: __MODULE__)
  end

  # 初始化 GenServer，设置 UDP 套接字
  def init(port) do
    ops = [
      :binary,
      :inet,
      active: 10,
      # ip: addr,
      broadcast: true,
    ]
    {:ok, socket} = :gen_udp.open(port, ops)

    # 启动一个接收循环
    {:ok, socket}
  end

  # 接收广播包
  def handle_info({:udp, socket, _ip, _port, msg}, socket) do
    IO.puts("Received broadcast message: #{inspect(msg)}")
    {:noreply, socket}
  end

  # 处理进程停止时关闭 UDP 套接字
  def terminate(_reason, socket) do
    :gen_udp.close(socket)
    :ok
  end
end
