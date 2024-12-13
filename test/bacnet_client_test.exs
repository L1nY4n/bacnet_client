defmodule BacnetClientTest do
  use ExUnit.Case
  doctest BacnetClient

  test "greets the world" do
    assert BacnetClient.hello() == :world
  end
end
