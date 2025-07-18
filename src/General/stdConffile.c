#include "stdConffile.h"

#include "stdPlatform.h"
#include "jk.h"
#include "stdString.h"

int stdConffile_OpenRead(char *fpath)
{
    return stdConffile_OpenMode(fpath, "r");
}

int stdConffile_OpenWrite(char *a1)
{
    if ( writeFile )
        return 0;

    writeFile = std_pHS->fileOpen(a1, "wb");
    if (writeFile)
    {
        _strncpy(stdConffile_aWriteFilename, a1, 127);
        stdConffile_aWriteFilename[127] = 0;
        return 1;
    }
    else
    {
        writeFile = 0;
        return 0;
    }
}

int stdConffile_OpenMode(char *fpath, char* mode)
{
    if ( stdConffile_bOpen )
    {
        _strcpy(&aFilenameStack[128 * stackLevel], stdConffile_pFilename);
        
        openFileStack[stackLevel] = openFile;
        linenumStack[stackLevel] = stdConffile_linenum;
        apBufferStack[stackLevel] = stdConffile_aLine;
        
        stdConffile_linenum = 0;
        openFile = 0;
        _memcpy((void *)(aEntryStack + ((STDCONF_LINEBUFFER_LEN+4) * stackLevel)), &stdConffile_entry, sizeof(stdConffileEntry));
        stackLevel++;
    }

    if (!_memcmp(fpath, "none", 5u))
    {
        openFile = 0;
    }
    else
    {
        openFile = std_pHS->fileOpen(fpath, mode);
        if (!openFile)
            goto fail_open;
    }

    stdConffile_aLine = (char*)std_pHS->alloc(STDCONF_LINEBUFFER_LEN);
    _strncpy(stdConffile_pFilename, fpath, 127);
    stdConffile_pFilename[127] = 0;
    stdConffile_linenum = 0;
    stdConffile_bOpen = 1;
    return 1;

fail_open:
    openFile = 0;
    if (!stdConffile_bOpen)
        return 0;

    if (!stackLevel)
        return 0;

    _strcpy(stdConffile_pFilename, &aFilenameStack[128 * (stackLevel-- - 1)]);
    
    openFile = openFileStack[stackLevel];
    stdConffile_linenum = linenumStack[stackLevel];
    stdConffile_aLine = apBufferStack[stackLevel];
    
    _memcpy(&stdConffile_entry, (const void *)(aEntryStack + ((STDCONF_LINEBUFFER_LEN+4) * stackLevel)), sizeof(stdConffileEntry));
    return 0;
}

void stdConffile_Close()
{
    if (!stdConffile_bOpen)
        return;

    if (openFile)
      std_pHS->fileClose(openFile);

    openFile = 0;
    std_pHS->free(stdConffile_aLine);
    
    if (!stackLevel)
    {
        stdConffile_bOpen = 0;
        return;
    }

    _strcpy(stdConffile_pFilename, &aFilenameStack[128 * (stackLevel-- - 1)]);
    openFile = openFileStack[stackLevel];
    stdConffile_linenum = linenumStack[stackLevel];
    stdConffile_aLine = apBufferStack[stackLevel];
    _memcpy(&stdConffile_entry, (const void *)(aEntryStack + ((STDCONF_LINEBUFFER_LEN+4) * stackLevel)), sizeof(stdConffileEntry));
}

void stdConffile_CloseWrite()
{
    if (writeFile)
    {
        std_pHS->fileClose(writeFile);
        writeFile = 0;
        _strncpy(stdConffile_aWriteFilename, "NOT_OPEN", 0x7Fu);
        stdConffile_aWriteFilename[127] = 0;
    }
}

int stdConffile_WriteLine(const char *line)
{
    return stdConffile_Write(line, _strlen(line));
}

int stdConffile_Write(const char* line, int amt)
{
    if ( !writeFile || !line )
        return 0;

    return (amt) == std_pHS->fileWrite(writeFile, (void *)line, (amt));
}

int stdConffile_Printf(char *fmt, ...)
{
    int len;
    va_list va;

    va_start(va, fmt);
    if ( !writeFile || !fmt ) {
        va_end(va);
        return 0;
    }

    len = __vsnprintf(printfBuffer, STDCONF_LINEBUFFER_LEN, fmt, va);
    va_end(va);
    return std_pHS->fileWrite(writeFile, printfBuffer, len) == len;
}

int stdConffile_Read(void* out, int len)
{
    if (stdConffile_bOpen && openFile)
        return std_pHS->fileRead(openFile, out, len) == len;
    else
        return 0;
}

int stdConffile_ReadArgsFromStr(char *str)
{
  int i;
  char *iter;
  char *valstr;

  i = 0;
  stdConffile_entry.numArgs = 0;
  iter = _strtok(str, ", \t\n\r");
  if ( iter )
  {
    stdConffileArg* arg = &stdConffile_entry.args[0];
    do
    {
      valstr = _strchr(iter, '=');
      if ( valstr )
      {
        *valstr = 0;
        arg->key = iter;
        arg->value = valstr + 1;
      }
      else
      {
        arg->key = iter;
        arg->value = iter;
      }
      ++i;
      ++arg;
      iter = _strtok(0, ", \t\n\r");
    }
    while ( iter );
  }
  stdConffile_entry.numArgs = i;
  return i;
}

int stdConffile_ReadArgs()
{
    if ( !stdConffile_ReadLine() )
        return 0;

    while (1)
    {
        if ( stdConffile_ReadArgsFromStr(stdConffile_aLine) )
            break;

        if ( !stdConffile_ReadLine() )
            return 0;
    }
    return 1;
}

int stdConffile_ReadLine()
{
  char *line_iter;
  int is_eol;
  int buf_left;
  char *find_comment;
  unsigned int line_len;

  line_iter = stdConffile_aLine;
  is_eol = 0;
  buf_left = (STDCONF_LINEBUFFER_LEN-1);
  while (buf_left)
  {
    if (!std_pHS->fileGets(openFile, line_iter, buf_left))
      return 0;

    ++stdConffile_linenum;
    if ( !(*line_iter == ';') && !(*line_iter == '#') 
         && !(*line_iter == '\n') && !(*line_iter == '\r') )
    {
      find_comment = _strchr(line_iter, '#');
      if ( find_comment )
        *find_comment = 0;
      stdString_CStrToLower(line_iter);

      line_len = _strlen(stdConffile_aLine);
      if (line_len >= 2 && stdConffile_aLine[line_len - 2] == '\\' ) // added: line_len >= 2
      {
        line_iter = &stdConffile_aLine[line_len - 2];
        buf_left = STDCONF_LINEBUFFER_LEN - line_len;
      }
      else
      {
        is_eol = 1;
        if (line_len >= 1 && (stdConffile_aLine[line_len - 1] == '\r' || stdConffile_aLine[line_len - 1] == '\n') ) // added: line_len >= 1
          stdConffile_aLine[line_len - 1] = 0;
      }
    }

    if (is_eol)
      return 1;
  }
  return 1;
}

int stdConffile_GetFileHandle()
{
  return openFile;
}
