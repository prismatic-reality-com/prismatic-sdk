defmodule PrismaticSDK.HTTP do
  @moduledoc """
  HTTP utilities and helpers for the Prismatic SDK.

  Provides common HTTP functionality used across the SDK including:
  - Request/response logging
  - Error handling utilities
  - Header manipulation
  - URL building helpers

  This module is primarily used internally by other SDK components.
  """

  require Logger

  @type headers :: [{String.t(), String.t()}] | map()
  @type url :: String.t()
  @type query_params :: map()

  @doc """
  Builds a URL with query parameters.

  ## Examples

      iex> PrismaticSDK.HTTP.build_url("https://api.example.com/search", %{q: "test", limit: 10})
      "https://api.example.com/search?limit=10&q=test"

  """
  @spec build_url(url(), query_params()) :: url()
  def build_url(base_url, params) when params == %{} do
    base_url
  end

  def build_url(base_url, params) when is_map(params) do
    query_string = URI.encode_query(params)
    "#{base_url}?#{query_string}"
  end

  @doc """
  Normalizes headers from various formats to a list of tuples.

  ## Examples

      iex> PrismaticSDK.HTTP.normalize_headers(%{"Content-Type" => "application/json"})
      [{"content-type", "application/json"}]

      iex> PrismaticSDK.HTTP.normalize_headers([{"Authorization", "Bearer token"}])
      [{"authorization", "Bearer token"}]

  """
  @spec normalize_headers(headers()) :: [{String.t(), String.t()}]
  def normalize_headers(headers) when is_map(headers) do
    Enum.map(headers, fn {key, value} ->
      {String.downcase(to_string(key)), to_string(value)}
    end)
  end

  def normalize_headers(headers) when is_list(headers) do
    Enum.map(headers, fn {key, value} ->
      {String.downcase(to_string(key)), to_string(value)}
    end)
  end

  @doc """
  Merges multiple header collections, with later headers overriding earlier ones.

  ## Examples

      iex> base = %{"content-type" => "application/json"}
      iex> auth = %{"authorization" => "Bearer token"}
      iex> PrismaticSDK.HTTP.merge_headers([base, auth])
      [{"authorization", "Bearer token"}, {"content-type", "application/json"}]

  """
  @spec merge_headers([headers()]) :: [{String.t(), String.t()}]
  def merge_headers(header_collections) do
    header_collections
    |> Enum.reduce(%{}, fn headers, acc ->
      normalized = headers |> normalize_headers() |> Map.new()
      Map.merge(acc, normalized)
    end)
    |> Map.to_list()
  end

  @doc """
  Gets a header value by name (case-insensitive).

  ## Examples

      iex> headers = [{"content-type", "application/json"}, {"authorization", "Bearer token"}]
      iex> PrismaticSDK.HTTP.get_header(headers, "Content-Type")
      "application/json"

      iex> PrismaticSDK.HTTP.get_header(headers, "x-not-found", "default")
      "default"

  """
  @spec get_header([{String.t(), String.t()}], String.t(), String.t()) :: String.t()
  def get_header(headers, name, default \\ nil) do
    normalized_name = String.downcase(name)

    case Enum.find(headers, fn {key, _value} -> String.downcase(key) == normalized_name end) do
      {_key, value} -> value
      nil -> default
    end
  end

  @doc """
  Extracts content type from headers.

  ## Examples

      iex> headers = [{"content-type", "application/json; charset=utf-8"}]
      iex> PrismaticSDK.HTTP.content_type(headers)
      "application/json"

  """
  @spec content_type([{String.t(), String.t()}]) :: String.t()
  def content_type(headers) do
    case get_header(headers, "content-type", "text/plain") do
      content_type when is_binary(content_type) ->
        content_type |> String.split(";") |> hd() |> String.trim()
      _ ->
        "text/plain"
    end
  end

  @doc """
  Logs an HTTP request for debugging.

  ## Examples

      PrismaticSDK.HTTP.log_request(:get, "https://api.example.com", [], "")

  """
  @spec log_request(atom(), url(), [{String.t(), String.t()}], String.t()) :: :ok
  def log_request(method, url, headers, body) do
    if Application.get_env(:prismatic_sdk, :log_requests, false) do
      Logger.debug([
        "HTTP Request: ",
        "#{String.upcase(to_string(method))} #{url}\n",
        format_headers_for_log(headers),
        if(byte_size(body) > 0, do: "\nBody: #{format_body_for_log(body)}", else: "")
      ])
    end

    :ok
  end

  @doc """
  Logs an HTTP response for debugging.

  ## Examples

      PrismaticSDK.HTTP.log_response(200, [{"content-type", "application/json"}], ~s({"status": "ok"}))

  """
  @spec log_response(integer(), [{String.t(), String.t()}], String.t()) :: :ok
  def log_response(status, headers, body) do
    if Application.get_env(:prismatic_sdk, :log_responses, false) do
      Logger.debug([
        "HTTP Response: ",
        "#{status}\n",
        format_headers_for_log(headers),
        if(byte_size(body) > 0, do: "\nBody: #{format_body_for_log(body)}", else: "")
      ])
    end

    :ok
  end

  @doc """
  Determines if a status code represents success.

  ## Examples

      iex> PrismaticSDK.HTTP.success_status?(200)
      true

      iex> PrismaticSDK.HTTP.success_status?(404)
      false

  """
  @spec success_status?(integer()) :: boolean()
  def success_status?(status) when status >= 200 and status < 300, do: true
  def success_status?(_status), do: false

  @doc """
  Determines if a status code represents a client error.

  ## Examples

      iex> PrismaticSDK.HTTP.client_error?(404)
      true

      iex> PrismaticSDK.HTTP.client_error?(500)
      false

  """
  @spec client_error?(integer()) :: boolean()
  def client_error?(status) when status >= 400 and status < 500, do: true
  def client_error?(_status), do: false

  @doc """
  Determines if a status code represents a server error.

  ## Examples

      iex> PrismaticSDK.HTTP.server_error?(500)
      true

      iex> PrismaticSDK.HTTP.server_error?(404)
      false

  """
  @spec server_error?(integer()) :: boolean()
  def server_error?(status) when status >= 500, do: true
  def server_error?(_status), do: false

  @doc """
  Creates a standardized error response.

  ## Examples

      PrismaticSDK.HTTP.error_response(404, "Not Found")
      # => {:error, {:client_error, 404, "Not Found"}}

  """
  @spec error_response(integer(), term()) :: {:error, term()}
  def error_response(status, body) do
    cond do
      status == 401 -> {:error, :unauthorized}
      status == 403 -> {:error, :forbidden}
      status == 404 -> {:error, :not_found}
      status == 429 -> {:error, :rate_limited}
      client_error?(status) -> {:error, {:client_error, status, body}}
      server_error?(status) -> {:error, {:server_error, status, body}}
      true -> {:error, {:unexpected_status, status, body}}
    end
  end

  @doc """
  Encodes a request body based on content type.

  ## Examples

      iex> PrismaticSDK.HTTP.encode_body(%{name: "test"}, "application/json")
      ~s({"name":"test"})

      iex> PrismaticSDK.HTTP.encode_body("plain text", "text/plain")
      "plain text"

  """
  @spec encode_body(term(), String.t()) :: String.t()
  def encode_body(nil, _content_type), do: ""
  def encode_body("", _content_type), do: ""

  def encode_body(body, content_type) when is_binary(content_type) do
    case String.downcase(content_type) do
      "application/json" ->
        if is_binary(body) do
          body
        else
          Jason.encode!(body)
        end

      "application/x-www-form-urlencoded" when is_map(body) ->
        URI.encode_query(body)

      _ ->
        to_string(body)
    end
  end

  def encode_body(body, _content_type), do: to_string(body)

  @doc """
  Decodes a response body based on content type.

  ## Examples

      iex> PrismaticSDK.HTTP.decode_body(~s({"name":"test"}), "application/json")
      {:ok, %{"name" => "test"}}

      iex> PrismaticSDK.HTTP.decode_body("plain text", "text/plain")
      {:ok, "plain text"}

  """
  @spec decode_body(String.t(), String.t()) :: {:ok, term()} | {:error, term()}
  def decode_body("", _content_type), do: {:ok, nil}

  def decode_body(body, content_type) when is_binary(body) and is_binary(content_type) do
    case String.downcase(content_type) |> String.split(";") |> hd() do
      "application/json" ->
        case Jason.decode(body) do
          {:ok, decoded} -> {:ok, decoded}
          {:error, reason} -> {:error, {:json_decode_error, reason}}
        end

      _ ->
        {:ok, body}
    end
  end

  def decode_body(body, _content_type), do: {:ok, body}

  @doc """
  Calculates retry delay with exponential backoff.

  ## Examples

      iex> PrismaticSDK.HTTP.retry_delay(1, 1000)
      2000

      iex> PrismaticSDK.HTTP.retry_delay(2, 1000, max_delay: 5000)
      4000

  """
  @spec retry_delay(non_neg_integer(), pos_integer(), keyword()) :: pos_integer()
  def retry_delay(attempt, base_delay_ms, opts \\ []) do
    max_delay = Keyword.get(opts, :max_delay, 30_000)
    jitter_factor = Keyword.get(opts, :jitter_factor, 0.1)

    # Exponential backoff: base_delay * 2^attempt
    delay = base_delay_ms * :math.pow(2, attempt)

    # Add jitter to prevent thundering herd
    jitter = delay * jitter_factor * :rand.uniform()
    final_delay = delay + jitter

    # Cap at max_delay
    min(round(final_delay), max_delay)
  end

  # Private helper functions

  defp format_headers_for_log(headers) do
    if Enum.empty?(headers) do
      "Headers: (none)"
    else
      formatted = Enum.map(headers, fn {key, value} ->
        # Hide sensitive headers
        display_value = if String.downcase(key) in ["authorization", "x-api-key"] do
          "[REDACTED]"
        else
          value
        end
        "  #{key}: #{display_value}"
      end)

      ["Headers:\n", Enum.join(formatted, "\n")]
    end
  end

  defp format_body_for_log(body) do
    max_body_length = Application.get_env(:prismatic_sdk, :max_log_body_length, 1000)

    if byte_size(body) > max_body_length do
      binary_part(body, 0, max_body_length) <> "... [truncated]"
    else
      body
    end
  end
end