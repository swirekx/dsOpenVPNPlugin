unit uDBSQLite;

//{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, SQLiteWrap;

procedure CheckDataBase(FileName:string);
function Login(FileName:string; aUserName, aPass:string):Integer;
procedure Connect(FileName:string; aUserName:String; ip:string; port:Integer; local_ip, remote_ip:string);
procedure Disconnect(FileName:string; aUserName:String; ip:string; port:Integer; b_send, b_reciv:Int64; time_dur:Integer);

implementation

procedure Disconnect(FileName:string; aUserName:String; ip:string; port:Integer; b_send, b_reciv:Int64; time_dur:Integer);
var
  db:TSqliteDatabase;
begin
  {SELECT conn_id FROM connections WHERE disconnect_time IS NULL AND user_id = ' + IntToStr(userId) +
                    ' AND untrusted_ip = ' + QuotedStr(ip) + ' AND untrusted_port = ' + IntToStr(port))}
   db:=TSqliteDatabase.Create(FileName);
  try
    db.ExecSQL('UPDATE connections SET bytes_sent = ' + IntToStr(b_send) + ', bytes_received = ' +
               IntToStr(b_reciv) + ', time_duration = time(' + IntToStr(time_dur) + ',''unixepoch'')' +
               ' , disconnect_time = datetime(''now'', ''localtime'') ' +
               ' WHERE disconnect_time IS NULL ' + #13#10 +
               ' AND user_id = (SELECT user_id FROM users WHERE username = ' + QuotedStr(aUserName) + ')' + #13#10 +
               ' AND untrusted_ip = ' + QuotedStr(ip) + ' AND untrusted_port = ' + IntToStr(port));
  finally
    db.Free;
  end;
end;

procedure Connect(FileName:string; aUserName:String; ip:string; port:Integer; local_ip, remote_ip:string);
var
  db:TSqliteDatabase;
begin
  db:=TSqliteDatabase.Create(FileName);
  try
    db.ExecSQL('INSERT INTO connections (user_id, connect_time, untrusted_ip, untrusted_port, ifconfig_pool_local_ip, ifconfig_pool_remote_ip) VALUES (' +#13#10+
               '(SELECT user_id FROM users WHERE username = ' + QuotedStr(aUserName) + '), datetime(''now'', ''localtime''),' + QuotedStr(ip) + ',' + IntToStr(port) + ',' + QuotedStr(local_ip) + ',' + QuotedStr(remote_ip) + ');');
  finally
    db.Free;
  end;
end;

function Login(FileName:string; aUserName, aPass:string):Integer;
var
  db:TSqliteDatabase;
begin
  Result:=-1;
  try
    db:=TSqliteDatabase.Create(FileName);
    Result:=db.GetTableValue('SELECT user_id FROM users WHERE active = 1 AND username = ' +
                    QuotedStr(aUserName) + ' AND password = ' + QuotedStr(aPass));
  finally
    db.Free;
  end;
end;

procedure CheckDataBase(FileName:string);
var
  db:TSqliteDatabase;
begin
  try
    db:=TSqliteDatabase.Create(FileName);
    db.ExecSQL('CREATE TABLE IF NOT EXISTS users ( ' + #13#10 +
               '  user_id INTEGER PRIMARY KEY  AUTOINCREMENT  NOT NULL  UNIQUE, ' + #13#10 +
               '  username VARCHAR(50) UNIQUE, ' + #13#10 +
               '  password VARCHAR(50), ' + #13#10 +
               '  active INTEGER, ' + #13#10 +
               '  description VARCHAR(500));');

    db.ExecSQL('CREATE TABLE IF NOT EXISTS connections ( ' + #13#10 +
               '  conn_id INTEGER PRIMARY KEY  AUTOINCREMENT  NOT NULL  UNIQUE, ' + #13#10 +
               '  user_id INTEGER, ' + #13#10 +
               '  connect_time DATETIME, ' + #13#10 +
               '  disconnect_time DATETIME, ' + #13#10 +
               '  untrusted_ip VARCHAR(20), ' + #13#10 +
               '  untrusted_port INTEGER, ' + #13#10 +
               '  ifconfig_pool_remote_ip VARCHAR(20), ' + #13#10 +
               '  ifconfig_pool_local_ip VARCHAR(20), ' + #13#10 +
               '  bytes_sent INT8, ' + #13#10 +
               '  bytes_received INT8, ' + #13#10 +
               '  time_duration DATETIME, ' + #13#10 +
               '  CONSTRAINT FK_connections_users FOREIGN KEY (user_id) REFERENCES users(user_id) ' + #13#10 +
               '); ');

    db.ExecSQL('CREATE TABLE IF NOT EXISTS log ( ' + #13#10 +
               '  id INTEGER PRIMARY KEY  AUTOINCREMENT  NOT NULL  UNIQUE,  ' + #13#10 +
               '  time DATETIME, ' + #13#10 +
               '  info VARCHAR(1000)); ');
  finally
    db.Free;
  end;
end;

end.

