
// ****************************************************************************
// File: Core.cpp
// Desc: Function String Associate plug-in
//
// ****************************************************************************
#include "stdafx.h"
#include <list>

#define MAX_LABEL_STR 64  /* Max size of each label */
#define MAX_COMMENT   256 /* Max size of comment line */

// GUID info container
struct tSTRINFO
{
	tSTRINFO::tSTRINFO(LPSTR pszString) : iReferences(1) 
	{ 
		qstrncpy(szString, pszString, (MAX_LABEL_STR - 1));
		szString[MAX_LABEL_STR - 1] = 0;
	}
	BOOL operator < (const tSTRINFO &rhs){ return(iReferences > rhs.iReferences); }

	char szString[MAX_LABEL_STR];
	int  iReferences;

	// Use IDA allocs
	static PVOID operator new(size_t size){	return(qalloc(size)); };
	static void operator delete(PVOID _Ptr){ return(qfree(_Ptr)); }
};
typedef std::list<tSTRINFO> STRLIST;


// === Function Prototypes ===
static BOOL CheckBreak();
static BOOL ProcessFuncion(func_t *pFunc);
static void FilterWhitespace(LPSTR pszString);
static LPCTSTR TimeString(TIMESTAMP Time);

// === Data ===
static ea_t s_uStartAddress = NULL;
static UINT uCommentCount = 0;


// Main dialog
static const char szMainDialog[] =
{	
	"BUTTON YES* Continue\n" // "Continue" instead of "okay"
	
	// Help block
	"HELP\n"
	"\"Function String Associate\"" 
	"Extracts strings from each function and intelligently adds them\nto the function comment line.\n"
	"\nBy Sirmabus @ http://www.openrce.org\n"
	"\nSee \"FunctionStringAssociate.txt\" for more information.\n"
	"ENDHELP\n"	

	// Title
	"<Function String Associate Plug-in>\n"

	// Message text
	"-Version: %A, %A, by Sirmabus-\n"
	"\nExtracts strings from each function and intelligently adds them\nto the function comment line.\n"
	
	"\n\n"
};


// Initialize
void CORE_Init()
{
}


// Un-initialize
void CORE_Exit()
{
}


// Plug-in process
void CORE_Process(int iArg)
{
	msg("\n== Function String Associate plug-in: v: %s - %s, By Sirmabus ==\n", MY_VERSION, __DATE__);
	//while(_kbhit()) getchar();

	if(autoIsOk())
	{		
		int iUIResult = AskUsingForm_c(szMainDialog, MY_VERSION, __DATE__);
		if(!iUIResult)
		{			
			msg(" - Canceled -\n");				
			return;
		}
	
		msg("\nWorking, <Press Pause/Break key to abort>...\n");
		// TODO: Add UI handler for "cancel"
		show_wait_box("Working..\nTake a smoke, drink some coffee, this could be a while..  \n\n<Press Pause/Break key to abort>"); 

		// Save starting point
		s_uStartAddress = get_screen_ea();   
				
		// Iterate through all functions..
		TIMESTAMP StartTime = GetTimeStamp();
		int iFuncCount = get_func_qty();		
		msg("Functions to process: %d\n", iFuncCount);
		for(int iIndex = 0; iIndex < iFuncCount; iIndex++)
		{
			if(func_t *pFunc = getn_func(iIndex))
			{			
				// Process it..
				if(!ProcessFuncion(pFunc))
					break;
		
				// Bail out on request
				if(CheckBreak())
					break;
			}
			else
			{
				msg("\n*** Failed to get function for index: %d! ***\n", iIndex);
				return; // **
			}
		}
		
		// Clean up
		// Restore starting point
		jumpto(s_uStartAddress, 0);
		hide_wait_box();

		msg("Comments generated: %d\n", uCommentCount);
		msg("        Total time: %s.\n", TimeString(GetTimeStamp() - StartTime));
		msg("Finsihed.\n-------------------------------------------------------------\n");		
	}
	else
	{
		warning("Autoanalysis must finish first before you run this plug-in!");
		msg("\n*** Aborted ***\n");
	}
}

// Checks and handles if break key pressed; returns TRUE on break.
static BOOL CheckBreak()
{
	if(GetAsyncKeyState(VK_PAUSE) & 0x8000)
	{			
		msg("\n*** Aborted ***\n\n");	
		return(TRUE);
	}

	return(FALSE);
}

// Get a nice line of disassembled code text sans color tags
static LPCTSTR GetDisasmText(ea_t ea)
{
	static char szBuff[MAXSTR];
	szBuff[0] = szBuff[MAXSTR - 1] = 0;
	generate_disasm_line(ea, szBuff, (sizeof(szBuff) - 1));
	tag_remove(szBuff, szBuff, (sizeof(szBuff) - 1));
	return(szBuff);
}

// Remove whitespace & illegal chars from input string
static void FilterWhitespace(LPSTR pszString)
{
	LPSTR pszPtr = pszString;
	while(*pszPtr)
	{
		// Replace unwanted chars with a space char
		char c = *pszPtr;
		if((c < ' ') || (c > '~'))
			*pszPtr = ' ';			
			
		pszPtr++;
	};
	
	// Trim any starting space(s)
	pszPtr = pszString;
	while(*pszPtr)
	{
		if(*pszPtr == ' ')		
			memmove(pszPtr, pszPtr+1, strlen(pszPtr));		
		else
			break;	
	};
	
	// Trim trailing space(s)
	pszPtr = (pszString + (strlen(pszString) - 1));
	while(pszPtr >= pszString)
	{
		if(*pszPtr == ' ')		
			*pszPtr-- = 0;		
		else
			break;		
	};
}


// Process function
static BOOL ProcessFuncion(func_t *pFunc)
{	
	// Reject tiny functions
	if(pFunc->size() >= 8)
	{	
		// Skip if it already has a comment
		// TODO: Could have option to just skip comment if one already exists
		BOOL bSkip = FALSE;
		LPSTR pszComment = get_func_cmt(pFunc, true);
		if(!pszComment)
			get_func_cmt(pFunc, false);

		if(pszComment)
		{
			//msg("CMT: \"%s\"\n", pszComment);

			// Ignore library comments as they are often wrong
			// Common lib name: "Microsoft VisualC 2-8/net runtime"
			// TODO: Add more common library names			
			if(strncmp(pszComment, "Microsoft VisualC ", SIZESTR("Microsoft VisualC ")) != 0)			
				bSkip = TRUE;			

			qfree(pszComment);
		}

		if(!bSkip)
		{
			// Iterate function body looking for string references
			ALIGN(16) STRLIST cStrList;
			ea_t CurrentEA = pFunc->startEA;	
			ea_t EndEA	   = pFunc->endEA;
			BOOL bLineOnce = FALSE;
			while((CurrentEA != BADADDR) && (CurrentEA < EndEA))
			{		
				// Has an xref?
				xrefblk_t xb;
				if(xb.first_from(CurrentEA, XREF_DATA))
				{				
					// A string (ASCII or unicode)?
					flags_t uFlags = get_flags_novalue(xb.to);
					if(isASCII(uFlags))
					{
						if(!bLineOnce)
						{
							bLineOnce = TRUE;
							//autoWait();
							jumpto(pFunc->startEA, 0);
							//msg("%08X %08X ================================\n", pFunc->startEA, pFunc->endEA);
						}

						//LPCTSTR pszLine = GetDisasmText(CurrentEA);
						//msg("%08X F: %08X, T: %08X, S: %d, \"%s\".\n", CurrentEA, uFlags, xb.to, get_item_size(xb.to), pszLine);

						// Get the string
						char szBuff[MAX_LABEL_STR];
						szBuff[MAX_LABEL_STR - 1] = 0;
						get_ascii_contents(xb.to, get_item_size(xb.to), ASCSTR_C, szBuff, SIZESTR(szBuff));
						if(szBuff[0])
						{
							// Clean it up
							FilterWhitespace(szBuff);

							if(strlen(szBuff) > 3)
							{
								// If already in the list, just update it's ref count
								BOOL bSkip = FALSE;
								STRLIST::iterator i = cStrList.begin();
								for (; i != cStrList.end( ); i++)
								{
									if(strncmp(i->szString, szBuff, strlen(i->szString)) == 0)
									{
										i->iReferences++;
										bSkip = TRUE;
										break;
									}
								}

								if(!bSkip)
								{	
									// Add it to the list
									tSTRINFO tStrInfo(szBuff);
									cStrList.push_front(tStrInfo);								

									// Bail out if we have many strings
									if(cStrList.size() >= 8)
										break;
								}
							}
						}						
					}
				}
				
				CurrentEA = next_head(CurrentEA, EndEA);
			};

			// Got at least one string?			
			if(cStrList.size() > 0)
			{
				// Sort by reference count
				cStrList.sort();
				
				// Concatenate a final comment string								
				char szComment[MAX_COMMENT + MAX_LABEL_STR] = {0};
				szComment[0] = '<';
				STRLIST::iterator i = cStrList.begin();
				for (; i != cStrList.end(); i++)
				{				
					int iFreeSize = ((MAX_COMMENT - strlen(szComment)) - 1);
					if((iFreeSize > 6) && (iFreeSize < (int) (strlen(i->szString) + 2)))
						break;
					else
					{						
						char szTemp[MAX_LABEL_STR];
						szTemp[MAX_LABEL_STR - 1] = 0;
						qsnprintf(szTemp, (MAX_LABEL_STR - 1), "\"%s\"", i->szString);
						qstrncat(szComment, szTemp, iFreeSize);
					}

					// Continue line?
					STRLIST::iterator j = i;
					if(++j != cStrList.end())
					{
						iFreeSize = ((MAX_COMMENT - strlen(szComment)) - 1);
						if(iFreeSize > 6)
							qstrncat(szComment, ", ", iFreeSize);
						else
							break;
					}
				}
				qstrncat(szComment, ">", SIZESTR(szComment));

				// Add comment
				//msg("%08X <%s>\n", pFunc->startEA, szComment);		
				del_func_cmt(pFunc, true);
				del_func_cmt(pFunc, false);
				set_func_cmt(pFunc, szComment, true);
				uCommentCount++;
			}

		} // Skip existing comment
	} // Tiny function

	return(TRUE);
}


// Get a pretty delta time string for output
static LPCTSTR TimeString(TIMESTAMP Time)
{
	static char szBuff[64];
	ZeroMemory(szBuff, sizeof(szBuff));

	if(Time >= HOUR)  
		_snprintf(szBuff, (sizeof(szBuff) - 1), "%.2f hours", (Time / (TIMESTAMP) HOUR));    
	else
		if(Time >= MINUTE)    
			_snprintf(szBuff, (sizeof(szBuff) - 1), "%.2f minutes", (Time / (TIMESTAMP) MINUTE));    
		else
			_snprintf(szBuff, (sizeof(szBuff) - 1), "%.2f seconds", Time);    

	return(szBuff);
}
