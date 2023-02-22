
#include <Demon.h>

#include <Core/WinUtils.h>
#include "Common/Defines.h"
#include <Core/MiniStd.h>
#include <Core/Package.h>
#include "Common/Macros.h"
#include <Core/Parser.h>

#include <Inject/InjectUtil.h>

#include <Loader/PeLdr.h>
#include <Loader/ObjectApi.h>

DWORD PeLdr( PCHAR EntryName, PVOID CoffeeData, PVOID ArgData, SIZE_T ArgSize )
{
	return 0;
}

VOID PeRunner( PCHAR EntryName, DWORD EntryNameSize, PVOID CoffeeData, SIZE_T CoffeeDataSize, PVOID ArgData, SIZE_T ArgSize )
{

}