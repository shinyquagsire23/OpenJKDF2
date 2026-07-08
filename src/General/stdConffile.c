#include "stdConffile.h"

#include "stdPlatform.h"
#include "jk.h"
#include "stdString.h"

// Added: Split off local file access from GOB access
static struct HostServices* stdConffile_pHS = 0;
static BOOL openFileIsBypass[20];
static BOOL bOpenFileIsBypassed = 0;

int stdConffile_Open(char *pFilename)
{
    return stdConffile_OpenMode(pFilename, "r");
}

int stdConffile_OpenWrite(char *pFilename)
{
    if ( writeFile )
        return 0;

    // Added: std_g_pHS -> pLowLevelHS
    stdConffile_pHS = pLowLevelHS;
    writeFile = stdConffile_pHS->fileOpen(pFilename, "wb");
    if (writeFile)
    {
        stdString_SafeStrCopy(stdConffile_aWriteFilename, pFilename, 128);
        return 1;
    }
    else
    {
        writeFile = 0;
        return 0;
    }
}

// Added: Helper
int stdConffile_OpenReadBytes(char *fpath)
{
    return stdConffile_OpenMode(fpath, "rb");
}

// Added: Split off local file access from GOB access
int stdConffile_OpenModeCommon(char *fpath, const char* mode, BOOL bBypassGobs)
{
    if ( stdConffile_bOpen )
    {
        _strcpy(&aFilenameStack[128 * stackLevel], stdConffile_pFilename);
        
        // Added: Split off local file access from GOB access
        openFileIsBypass[stackLevel] = stdConffile_pHS == pLowLevelHS ? 1 : 0;
        openFileStack[stackLevel] = openFile;
        linenumStack[stackLevel] = stdConffile_linenum;
        apBufferStack[stackLevel] = stdConffile_g_aLine;
        
        stdConffile_linenum = 0;
        openFile = 0;
        _memcpy((void *)(aEntryStack + ((STDCONF_LINEBUFFER_LEN+4) * stackLevel)), &stdConffile_g_entry, sizeof(StdConffileEntry));
        stackLevel++;
    }

    // Added: Setting stdConffile_pHS
    if (bBypassGobs) {
        stdConffile_pHS = pLowLevelHS;
    }
    else {
        stdConffile_pHS = std_g_pHS;
    }

    if (!_memcmp(fpath, "none", 5u))
    {
        openFile = 0;
    }
    else
    {
        openFile = stdConffile_pHS->fileOpen(fpath, mode); // Added: std_g_pHS -> stdConffile_pHS
        if (!openFile)
            goto fail_open;
    }

    stdConffile_g_aLine = (char*)STD_ALLOC(STDCONF_LINEBUFFER_LEN);
    stdString_SafeStrCopy(stdConffile_pFilename, fpath, 128);
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
    stdConffile_g_aLine = apBufferStack[stackLevel];
    stdConffile_pHS = openFileIsBypass[stackLevel] ? pLowLevelHS : std_g_pHS; // Added: Split off local file access from GOB access

    _memcpy(&stdConffile_g_entry, (const void *)(aEntryStack + ((STDCONF_LINEBUFFER_LEN+4) * stackLevel)), sizeof(StdConffileEntry));
    return 0;
}

int stdConffile_OpenMode(char *pFilename, const char* openMode)
{
    return stdConffile_OpenModeCommon(pFilename, openMode, 0);
}

// Added
int stdConffile_OpenModeBypass(char *fpath, const char* mode)
{
    return stdConffile_OpenModeCommon(fpath, mode, 1);
}

int stdConffile_OpenReadBypass(char *fpath)
{
    return stdConffile_OpenModeBypass(fpath, "r");
}

int stdConffile_OpenWriteBypass(char *a1)
{
    return stdConffile_OpenWrite(a1);
}

// Added: Helper
int stdConffile_OpenReadBytesBypass(char *fpath)
{
    return stdConffile_OpenModeBypass(fpath, "rb");
}

void stdConffile_Close()
{
    if (!stdConffile_bOpen)
        return;

    if (openFile) {
        stdConffile_pHS->fileClose(openFile); // Added: std_g_pHS -> stdConffile_pHS
    }

    openFile = 0;
    STD_FREE(stdConffile_g_aLine);
    
    if (!stackLevel)
    {
        stdConffile_bOpen = 0;
        return;
    }

    _strcpy(stdConffile_pFilename, &aFilenameStack[128 * (stackLevel-- - 1)]);
    openFile = openFileStack[stackLevel];
    stdConffile_linenum = linenumStack[stackLevel];
    stdConffile_g_aLine = apBufferStack[stackLevel];
    stdConffile_pHS = openFileIsBypass[stackLevel] ? pLowLevelHS : std_g_pHS; // Added: Split off local file access from GOB access
    _memcpy(&stdConffile_g_entry, (const void *)(aEntryStack + ((STDCONF_LINEBUFFER_LEN+4) * stackLevel)), sizeof(StdConffileEntry));
}

void stdConffile_CloseWrite()
{
    if (writeFile)
    {
        stdConffile_pHS->fileClose(writeFile); // Added: std_g_pHS -> stdConffile_pHS
        writeFile = 0;
        stdString_SafeStrCopy(stdConffile_aWriteFilename, "NOT_OPEN", 128);
    }
}

int stdConffile_WriteLine(const char *pLine)
{
    return stdConffile_Write(pLine, _strlen(pLine));
}

int stdConffile_Write(const char* pData, int size)
{
    if ( !writeFile || !pData )
        return 0;

    // Added: std_g_pHS -> stdConffile_pHS
    return (size) == stdConffile_pHS->fileWrite(writeFile, (void *)pData, (size));
}

int stdConffile_Printf(char *pFormat, ...)
{
    int len;
    va_list va;

    va_start(va, pFormat);
    if ( !writeFile || !pFormat ) {
        va_end(va);
        return 0;
    }

    len = __vsnprintf(printfBuffer, STDCONF_LINEBUFFER_LEN, pFormat, va);
    va_end(va);

    // Added: std_g_pHS -> stdConffile_pHS
    return stdConffile_pHS->fileWrite(writeFile, printfBuffer, len) == len;
}

int stdConffile_Read(void* pData, int size)
{
    // Added: std_g_pHS -> stdConffile_pHS
    if (stdConffile_bOpen && openFile)
        return stdConffile_pHS->fileRead(openFile, pData, size) == size;
    else
        return 0;
}

int stdConffile_ReadArgsFromStr(char *pStr)
{
  int i;
  char *iter;
  char *valstr;

  i = 0;
  stdConffile_g_entry.numArgs = 0;
  iter = _strtok(pStr, ", \t\n\r");
  if ( iter )
  {
    StdConffileArg* arg = &stdConffile_g_entry.aArgs[0];
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
  stdConffile_g_entry.numArgs = i;
  return i;
}

int stdConffile_ReadArgs()
{
    if ( !stdConffile_ReadLine() )
        return 0;

    while (1)
    {
        if ( stdConffile_ReadArgsFromStr(stdConffile_g_aLine) )
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

  line_iter = stdConffile_g_aLine;
  is_eol = 0;
  buf_left = (STDCONF_LINEBUFFER_LEN-1);
  while (buf_left)
  {
    // Added: std_g_pHS -> stdConffile_pHS
    if (!stdConffile_pHS->fileGets(openFile, line_iter, buf_left))
      return 0;

    ++stdConffile_linenum;
    if ( !(*line_iter == ';') && !(*line_iter == '#') 
         && !(*line_iter == '\n') && !(*line_iter == '\r') )
    {
      find_comment = _strchr(line_iter, '#');
      if ( find_comment )
        *find_comment = 0;
      stdString_CStrToLower(line_iter);

      line_len = _strlen(stdConffile_g_aLine);
      if (line_len >= 2 && stdConffile_g_aLine[line_len - 2] == '\\' ) // added: line_len >= 2
      {
        line_iter = &stdConffile_g_aLine[line_len - 2];
        buf_left = STDCONF_LINEBUFFER_LEN - line_len;
      }
      else
      {
        is_eol = 1;
        if (line_len >= 1 && (stdConffile_g_aLine[line_len - 1] == '\r' || stdConffile_g_aLine[line_len - 1] == '\n') ) // added: line_len >= 1
          stdConffile_g_aLine[line_len - 1] = 0;
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
