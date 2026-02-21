defmodule PrismaticSDK.Auth do
  @moduledoc """
  Authentication handling for the Prismatic Platform SDK.

  Supports multiple authentication methods:

  - **API Keys** - For service-to-service authentication
  - **JWT Bearer Tokens** - For user-based authentication
  - **Basic Auth** - For legacy systems
  - **OAuth 2.0** - For third-party integrations (planned)

  ## Usage

      # API Key authentication
      auth = PrismaticSDK.Auth.api_key("pk_live_...")

      # JWT Bearer token
      auth = PrismaticSDK.Auth.bearer_token("eyJ0eXAi...")

      # Basic authentication
      auth = PrismaticSDK.Auth.basic_auth("username", "password")

      # Get headers for HTTP requests
      headers = PrismaticSDK.Auth.headers(auth)
      # => %{"authorization" => "Bearer pk_live_..."}

  ## Authentication Flow

      # 1. Authenticate with credentials
      {:ok, token} = PrismaticSDK.Auth.authenticate(client, %{
        username: "user@example.com",
        password: "secure_password"
      })

      # 2. Use token for subsequent requests
      client = PrismaticSDK.Client.new(bearer_token: token)

      # 3. Refresh token when needed
      {:ok, new_token} = PrismaticSDK.Auth.refresh_token(client, token)

  """

  alias PrismaticSDK.Client

  @type t :: %__MODULE__{
    type: :api_key | :bearer_token | :basic_auth,
    credentials: term()
  }

  @type auth_params :: %{
    optional(:username) => String.t(),
    optional(:password) => String.t(),
    optional(:email) => String.t(),
    optional(:mfa_code) => String.t()
  }

  @type token_response :: %{
    access_token: String.t(),
    token_type: String.t(),
    expires_in: pos_integer(),
    refresh_token: String.t() | nil,
    scope: String.t() | nil
  }

  @enforce_keys [:type, :credentials]
  defstruct [:type, :credentials]

  @doc """
  Creates API key authentication.

  ## Examples

      auth = PrismaticSDK.Auth.api_key("pk_live_1234567890")

  """
  @spec api_key(String.t()) :: t()
  def api_key(key) when is_binary(key) do
    %__MODULE__{
      type: :api_key,
      credentials: key
    }
  end

  @doc """
  Creates Bearer token authentication (JWT).

  ## Examples

      auth = PrismaticSDK.Auth.bearer_token("eyJ0eXAiOiJKV1Qi...")

  """
  @spec bearer_token(String.t()) :: t()
  def bearer_token(token) when is_binary(token) do
    %__MODULE__{
      type: :bearer_token,
      credentials: token
    }
  end

  @doc """
  Creates Basic authentication.

  ## Examples

      auth = PrismaticSDK.Auth.basic_auth("username", "password")

  """
  @spec basic_auth(String.t(), String.t()) :: t()
  def basic_auth(username, password) when is_binary(username) and is_binary(password) do
    %__MODULE__{
      type: :basic_auth,
      credentials: {username, password}
    }
  end

  @doc """
  Returns HTTP headers for the authentication method.

  ## Examples

      headers = PrismaticSDK.Auth.headers(auth)
      # => %{"authorization" => "Bearer pk_live_..."}

  """
  @spec headers(t()) :: map()
  def headers(%__MODULE__{type: :api_key, credentials: key}) do
    %{"authorization" => "Bearer #{key}"}
  end

  def headers(%__MODULE__{type: :bearer_token, credentials: token}) do
    %{"authorization" => "Bearer #{token}"}
  end

  def headers(%__MODULE__{type: :basic_auth, credentials: {username, password}}) do
    encoded = Base.encode64("#{username}:#{password}")
    %{"authorization" => "Basic #{encoded}"}
  end

  @doc """
  Authenticates with username/password and returns a JWT token.

  ## Parameters

  - `client` - Configured SDK client
  - `params` - Authentication parameters

  ## Examples

      {:ok, token} = PrismaticSDK.Auth.authenticate(client, %{
        username: "user@example.com",
        password: "secure_password"
      })

      # With MFA
      {:ok, token} = PrismaticSDK.Auth.authenticate(client, %{
        username: "user@example.com",
        password: "secure_password",
        mfa_code: "123456"
      })

  ## Response

      {:ok, %{
        access_token: "eyJ0eXAi...",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "rt_...",
        scope: "read write"
      }}

  """
  @spec authenticate(Client.t(), auth_params()) :: {:ok, token_response()} | {:error, term()}
  def authenticate(client, params) do
    body = %{
      grant_type: "password",
      username: params[:username] || params[:email],
      password: params[:password]
    }

    # Add MFA code if provided
    body = if params[:mfa_code] do
      Map.put(body, :mfa_code, params[:mfa_code])
    else
      body
    end

    case Client.post(client, "/api/v1/auth/token", body) do
      {:ok, response} ->
        token_response = %{
          access_token: response["access_token"],
          token_type: response["token_type"] || "Bearer",
          expires_in: response["expires_in"] || 3600,
          refresh_token: response["refresh_token"],
          scope: response["scope"]
        }
        {:ok, token_response}

      {:error, {:client_error, 401, error_data}} ->
        {:error, parse_auth_error(error_data)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Refreshes an access token using a refresh token.

  ## Examples

      {:ok, new_token} = PrismaticSDK.Auth.refresh_token(client, refresh_token)

  """
  @spec refresh_token(Client.t(), String.t()) :: {:ok, token_response()} | {:error, term()}
  def refresh_token(client, refresh_token) when is_binary(refresh_token) do
    body = %{
      grant_type: "refresh_token",
      refresh_token: refresh_token
    }

    case Client.post(client, "/api/v1/auth/token", body) do
      {:ok, response} ->
        token_response = %{
          access_token: response["access_token"],
          token_type: response["token_type"] || "Bearer",
          expires_in: response["expires_in"] || 3600,
          refresh_token: response["refresh_token"] || refresh_token,
          scope: response["scope"]
        }
        {:ok, token_response}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Validates a JWT token without making a network request.

  ## Examples

      case PrismaticSDK.Auth.validate_token(token) do
        {:ok, token_claims} ->
          IO.puts("Token is valid")
        {:error, :expired} ->
          IO.puts("Token has expired")
        {:error, :invalid} ->
          IO.puts("Token is invalid")
      end

  """
  @spec validate_token(String.t()) :: {:ok, map()} | {:error, :expired | :invalid | term()}
  def validate_token(token) when is_binary(token) do
    try do
      # Basic JWT structure validation
      case String.split(token, ".") do
        [_header, payload, _signature] ->
          with {:ok, decoded} <- Base.url_decode64(payload, padding: false),
               {:ok, claims} <- Jason.decode(decoded) do

            current_time = System.system_time(:second)
            exp = claims["exp"]

            cond do
              is_nil(exp) ->
                {:ok, claims}

              exp <= current_time ->
                {:error, :expired}

              true ->
                {:ok, claims}
            end
          else
            _ -> {:error, :invalid}
          end

        _ ->
          {:error, :invalid}
      end
    rescue
      _ ->
        {:error, :invalid}
    end
  end

  @doc """
  Revokes an access token.

  ## Examples

      :ok = PrismaticSDK.Auth.revoke_token(client, token)

  """
  @spec revoke_token(Client.t(), String.t()) :: :ok | {:error, term()}
  def revoke_token(client, token) when is_binary(token) do
    body = %{token: token}

    case Client.post(client, "/api/v1/auth/revoke", body) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Gets the current user information using the client's authentication.

  ## Examples

      {:ok, user} = PrismaticSDK.Auth.get_current_user(client)
      # => %{
      #   "id" => "user_123",
      #   "email" => "user@example.com",
      #   "name" => "John Doe",
      #   "roles" => ["user", "admin"],
      #   "permissions" => ["read:perimeter", "write:labs"]
      # }

  """
  @spec get_current_user(Client.t()) :: {:ok, map()} | {:error, term()}
  def get_current_user(client) do
    Client.get(client, "/api/v1/auth/user")
  end

  @doc """
  Checks if the current authentication has a specific permission.

  ## Examples

      {:ok, true} = PrismaticSDK.Auth.has_permission?(client, "read:perimeter")
      {:ok, false} = PrismaticSDK.Auth.has_permission?(client, "admin:billing")

  """
  @spec has_permission?(Client.t(), String.t()) :: {:ok, boolean()} | {:error, term()}
  def has_permission?(client, permission) when is_binary(permission) do
    case Client.get(client, "/api/v1/auth/permissions/#{permission}") do
      {:ok, %{"allowed" => allowed}} when is_boolean(allowed) ->
        {:ok, allowed}

      {:ok, _} ->
        {:ok, false}

      {:error, :not_found} ->
        {:ok, false}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Creates a new API key for the current user.

  ## Examples

      {:ok, api_key} = PrismaticSDK.Auth.create_api_key(client, %{
        name: "Production API Key",
        permissions: ["read:perimeter", "write:labs"],
        expires_at: ~U[2026-12-31 23:59:59Z]
      })

  """
  @spec create_api_key(Client.t(), map()) :: {:ok, map()} | {:error, term()}
  def create_api_key(client, params) do
    Client.post(client, "/api/v1/auth/api-keys", params)
  end

  @doc """
  Lists all API keys for the current user.

  ## Examples

      {:ok, api_keys} = PrismaticSDK.Auth.list_api_keys(client)

  """
  @spec list_api_keys(Client.t()) :: {:ok, [map()]} | {:error, term()}
  def list_api_keys(client) do
    case Client.get(client, "/api/v1/auth/api-keys") do
      {:ok, %{"api_keys" => keys}} when is_list(keys) ->
        {:ok, keys}

      {:ok, keys} when is_list(keys) ->
        {:ok, keys}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Revokes an API key.

  ## Examples

      :ok = PrismaticSDK.Auth.revoke_api_key(client, "key_id_123")

  """
  @spec revoke_api_key(Client.t(), String.t()) :: :ok | {:error, term()}
  def revoke_api_key(client, key_id) when is_binary(key_id) do
    case Client.delete(client, "/api/v1/auth/api-keys/#{key_id}") do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  # Private functions

  defp parse_auth_error(%{"error" => error, "error_description" => description}) do
    case error do
      "invalid_grant" -> {:invalid_credentials, description}
      "mfa_required" -> {:mfa_required, description}
      "mfa_invalid" -> {:invalid_mfa_code, description}
      "account_locked" -> {:account_locked, description}
      _ -> {:auth_error, error, description}
    end
  end

  defp parse_auth_error(%{"error" => error}) do
    {:auth_error, error}
  end

  defp parse_auth_error(error_data) do
    {:auth_error, error_data}
  end
end