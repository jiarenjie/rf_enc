%%%-------------------------------------------------------------------
%%% @author jiarj
%%% @copyright (C) 2017, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 05. 四月 2017 9:34
%%%-------------------------------------------------------------------
-module(filemanager).
-author("jiarj").

%% API
-export([deleteDir/1,copyDir/2]).



%%拷贝文件夹 FromDir要拷贝的文件夹路径 TarDir 拷贝到的目标文件夹
copyDir(FromDir,TarDir)->

  %%获取当前文件夹的所有文件列表(包括子文件夹)
  {ok,AllFile} = file:list_dir_all(FromDir),
  %%创建目标文件夹
  file:make_dir(TarDir),
  %%尾递归遍历所有文件
  loopCopy(AllFile,FromDir,TarDir).

loopCopy(AllFile,FromDir,TarDir) ->
  case AllFile of
    [] ->
      ok;
    _ ->
      %%每次拿第一个文件  One
      [One|Other]=AllFile,
      Path=FromDir++"/"++One,
      Tar=TarDir++"/"++One,
      %%判断当前文件是否是文件夹
      IsDir= filelib:is_dir(Path),

      %%if写法  所有判断的可能写在前面  true写在后面
      if IsDir =:= false->
        %%如果当前是文件  则拷贝到目标路径
        file:copy(Path, Tar);
      %%if 的默认值
        true->
          %%如果当前是文件夹 在目标路径创建文件夹  并拷贝当前文件夹
          file:make_dir(Tar),
          copyDir(Path,Tar)
      end,

%%case写法

%%          case filelib:is_dir(Path) of
%%              true ->
%%                  file:make_dir(Tar),
%%                  copyDir(Path,Tar);
%%              _ ->
%%                  file:copy(Path, Tar)
%%          end,

      %%递归第一个文件后面的文件
      loopCopy(Other,FromDir,TarDir)
  end.






deleteDir(FromDir) ->

        %%获取当前文件夹的所有文件列表(包括子文件夹)
        {ok,AllFile} = file:list_dir_all(FromDir),
        %%尾递归遍历所有文件
        loopDelete(AllFile,FromDir).



loopDelete(AllFile, FromDir) ->
  case AllFile of
    [] ->
      %%把文件夹删了
      file:del_dir(FromDir),
      ok;
    _ ->
      %%每次拿第一个文件  One
      [One|Other]=AllFile,
      Path=FromDir++"/"++One,
      %%判断当前文件是否是文件夹
      IsDir= filelib:is_dir(Path),

      %%if写法  所有判断的可能写在前面  true写在后面
      if IsDir =:= false->
        %%如果当前是文件  把文件删了
        file:delete(Path);
      %%if 的默认值
        true->
          %%如果当前是文件夹 把文件夹里的文件删了 再把文件夹删了
          deleteDir(Path),
          file:del_dir(Path)
      end,

%%case写法

%%          case filelib:is_dir(Path) of
%%              true ->
%%                  file:make_dir(Tar),
%%                  copyDir(Path,Tar);
%%              _ ->
%%                  file:copy(Path, Tar)
%%          end,

      %%递归第一个文件后面的文件
      loopDelete(Other,FromDir)
  end.