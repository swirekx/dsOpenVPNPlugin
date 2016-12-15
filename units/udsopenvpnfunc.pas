unit udsOpenVPNFunc;

//{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Windows, uDBSQLite;

const
  OPENVPN_PLUGIN_UP                    = 0;
  OPENVPN_PLUGIN_DOWN                  = 1;
  OPENVPN_PLUGIN_ROUTE_UP              = 2;
  OPENVPN_PLUGIN_IPCHANGE              = 3;
  OPENVPN_PLUGIN_TLS_VERIFY            = 4;
  OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY = 5;
  OPENVPN_PLUGIN_CLIENT_CONNECT        = 6;
  OPENVPN_PLUGIN_CLIENT_DISCONNECT     = 7;
  OPENVPN_PLUGIN_LEARN_ADDRESS         = 8;
  OPENVPN_PLUGIN_N                     = 9;
  OPENVPN_PLUGIN_TLS_FINAL             = 10;
  OPENVPN_PLUGIN_ENABLE_PF             = 11;
  OPENVPN_PLUGIN_ROUTE_PREDOWN         = 12;
  OPENVPN_PLUGIN_FUNC_SUCCESS          = 0;
  OPENVPN_PLUGIN_FUNC_ERROR            = 1;

type
  TConfig = record
    aType   :(SQLite, MSSSQL);
    DataBase:string;
    Server  :string;
    UserName:string;
    Password:string;
  end;

function openvpn_plugin_open_v1 (var type_mask: Cardinal; const argv:Pointer; const envp:Pointer):Pointer; cdecl;
function openvpn_plugin_func_v1 (handle:Pointer; const _type:Integer; const argv:Pointer; const envp:Pointer): Cardinal; cdecl;
procedure openvpn_plugin_close_v1 (handle:Pointer); cdecl;
procedure openvpn_plugin_abort_v1 (handle:Pointer); cdecl;


implementation

procedure ZapiszDoPliku(Cosik:string);
var
  fs: TFileStream;
  NazwaPliku:string;
begin
  Cosik:=Cosik+#13#10;
  NazwaPliku:=ChangeFileExt(GetModuleName(HINSTANCE),'_ds.log');
  try
    if FileExists(NazwaPliku) then
    begin
      fs:=TFileStream.Create(NazwaPliku, fmOpenWrite);
      fs.Position:=fs.Size;
    end
    else
      fs:=TFileStream.Create(NazwaPliku, fmCreate or fmOpenWrite);
    fs.Write(PChar(Cosik)^, Length(Cosik)*SizeOf(Char));
  finally
    FreeAndNil(fs);
  end;
end;

function UNIXTimeToDateTimeFAST(UnixTimeStr: String): TDateTime;
var
  UnixTime: Int64;
  GMTST: TSystemTime;
  LocalST: TSystemTime;
begin
  Result:=0;
  if TryStrToInt64(UnixTimeStr, UnixTime) then
     Result := (UnixTime / 86400) + 25569;

  DateTimeToSystemTime(Result, GMTST);
  Win32Check(SystemTimeToTzSpecificLocalTime(nil, GMTST, LocalST));
  Result := SystemTimeToDateTime(LocalST);
end;

function get_env(const name:string; const envp:Pointer):AnsiString;
type
  PPAnsiCharArray = ^TPAnsiCharArray;
  TPAnsiCharArray = array[0..MaxInt div SizeOf(PAnsiChar) - 1] of PAnsiChar;
var
  i:integer;
  envpEntry:AnsiString;
  loc:PPAnsiCharArray;
begin
  loc:=envp;
  Result:='';
  try
    i:=0;
    while True do
    begin
      envpEntry:=loc^[i];
      if SameText(Name, Copy(envpEntry, 1, Length(Name))) then
      begin
        Result:=Copy(envpEntry, Length(Name) + 2, Length(envpEntry)-Length(Name)-1);
        Break;
      end;
      Inc(i);
    end;
  except
  end;
end;


function OPENVPN_PLUGIN_MASK(i:Integer):Integer;
begin
  Result:= 1 shl i;
end;

function openvpn_plugin_open_v1 (var type_mask: Cardinal; const argv:Pointer; const envp:Pointer):Pointer; cdecl;
var
  ConfigPtr : ^TConfig;
begin
  New(ConfigPtr);
  type_mask:=OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT) or
             OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) or
             OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT);
  Result:= ConfigPtr;
  if get_env('Type', argv) = 'SQLite' then
  begin
    ConfigPtr^.aType:=SQLite;
    ConfigPtr^.DataBase:=get_env('DataBase', argv);
    CheckDataBase(ConfigPtr^.DataBase);
  end;
end;

function openvpn_plugin_func_v1 (handle:Pointer; const _type:Integer; const argv:Pointer; const envp:Pointer): Cardinal; cdecl;
var
  user_id:Integer;
  ConfigPtr : ^TConfig;
begin
  ConfigPtr:=handle;
  Result:=OPENVPN_PLUGIN_FUNC_ERROR;

  if _type = OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY then
  begin
    if ConfigPtr^.aType = SQLite then
    begin
      user_id:= Login(ConfigPtr^.DataBase, get_env('username', envp), get_env('password', envp));
      if user_id > 0 then
         Result:=OPENVPN_PLUGIN_FUNC_SUCCESS;
    end;
  end
  else
  if _type = OPENVPN_PLUGIN_CLIENT_CONNECT then
  begin
    if ConfigPtr^.aType = SQLite then
    begin
      Connect(ConfigPtr^.DataBase,
              get_env('username',envp),
              get_env('untrusted_ip',envp),
              StrToInt(get_env('untrusted_port',envp)),
              get_env('ifconfig_pool_remote_ip',envp),
              get_env('ifconfig_pool_local_ip',envp));
    end;
    Result:=OPENVPN_PLUGIN_FUNC_SUCCESS;
  end
  else
  if _type = OPENVPN_PLUGIN_CLIENT_DISCONNECT then
  begin
     if ConfigPtr^.aType = SQLite then
    begin
      Disconnect(ConfigPtr^.DataBase,
                 get_env('username',envp),
                 get_env('untrusted_ip',envp),
                 StrToInt(get_env('untrusted_port',envp)),
                 StrToInt64(get_env('bytes_sent',envp)),
                 StrToInt64(get_env('bytes_received',envp)),
                 StrToInt(get_env('time_duration',envp)));
    end;
    Result:=OPENVPN_PLUGIN_FUNC_SUCCESS;
  end;
end;

procedure openvpn_plugin_close_v1 (handle:Pointer);cdecl;
var
  ConfigPtr : ^TConfig;
begin
  ConfigPtr:=handle;
  Dispose(ConfigPtr);
end;

procedure openvpn_plugin_abort_v1 (handle:Pointer); cdecl;
begin
  ZapiszDoPliku('openvpn_plugin_abort_v1');
end;

end.

