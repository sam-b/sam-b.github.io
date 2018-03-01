# My first Windows driver: Creating the Pink Screen Of Death

So a while ago I saw a cool blog post from [Mark Russinovich](https://twitter.com/markrussinovich) - [“Blue Screens” in Designer Colors with One Click](https://blogs.technet.microsoft.com/markrussinovich/2011/01/09/blue-screens-in-designer-colors-with-one-click/) where he changed the colors of the infamous BSOD, I went to look at the source of NotMyFault and soon found that everything but the code responsible for the color change was included :( [@ptsecurity_uk](https://twitter.com/PTsecurity_UK) has also looked at reversing Mark's code in the past and published some details on their blog: [Customizing Blue Screen of Death](http://blog.ptsecurity.com/2012/06/customizing-blue-screen-of-death.html) but again this didn't include buildable and runnable code :(

So the goal for this post is too create a simple driver which supports two different IOCTL codes (explained below) which when triggered in the correct order cause Windows to crash and then show a screen which looks like the one below.
![](/content/images/2016/09/psod-1-2.PNG)

All the code for this post can be found [here](https://github.com/sam-b/PSOD).
#### Creating a driver
To follow along with this you'll need a reasonably new version of Visual Studio and the Driver Development Kit installed. We start off by creating a new creating a new project with type 'Visual C++'->'Driver'->'WDF'(Windows Driver Framework)->'Kernel Mode Driver, Empty', then pick a name and click 'OK'. Now add a new file to the 'Source Files' directory called 'Driver.c', let's start by including the header files we will need.

<pre>
#include &lt;ntddk.h>
#include &lt;wdf.h>
</pre>

'ntddk.h' is the header file for the 'Windows Device Driver Kit' and 'wdf.h' is the header file for the 'Windows Driver Frameworks', between them they include all the external type and function definitions we will need.

Next we declare the two functions which are required for us to have a driver which runs in kernel mode, however briefly.

<pre>
NTSTATUS    DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);

EVT_WDF_DRIVER_DEVICE_ADD KmdfPSODEvtDeviceAdd;
</pre>

[DriverEntry](https://msdn.microsoft.com/en-us/library/windows/hardware/ff544113(v=vs.85).aspx) is the first function called when a driver is loaded and is responsbile for initializing the driver. At the moment all we want to do in DriverEntry is the bare minimum requried to create a driver.

<pre>
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;

	WDF_DRIVER_CONFIG_INIT(&config, KmdfPSODEvtDeviceAdd);
	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    return status;
}
</pre>
In DriverEntry we used the [WDF_DRIVER_CONFIG_INIT ](https://msdn.microsoft.com/en-us/library/windows/hardware/ff551302(v=vs.85).aspx) function to setup the drivers config, the KmdfPSODEvtDeviceAdd function is responsible for setting this up.
<pre>
NTSTATUS KmdfPSODEvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
	UNREFERENCED_PARAMETER(Driver);

	NTSTATUS status;
	WDFDEVICE hDevice;

	status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &hDevice);
	return status;
}
</pre>
We don't have special requirements for our driver so we just create it as a device with no special attributes. Now we should be able to build the driver which currently does nothing.
####Using a driver
In order to use our driver we need to enable test signing by running the following command in an Administrator command prompt.
<pre>
bcdedit.exe -set TESTSIGNING ON 
</pre>
In order to register and start the driver I used [OSRLoader](https://www.osronline.com/article.cfm?article=157), by selecting the .sys file we just built, I was able to register and then start the driver which did nothing as expected.

![](/content/images/2016/09/psod_osrloader-1.PNG)

#### Changing the BSOD
In order to work how Mark's myfault.sys driver did the color change I needed to do some reversing. I started by opening it up in IDA and using my 'totes 1337' reversing skills went straight to the 'strings' subview. I immediately saw the string 'Myfault Color Switcher':
![](/content/images/2016/09/psod_my_fault_strings.PNG)
There was only one cross reference to the string in the binary and it was exactly the function I was looking for.
![](/content/images/2016/09/psod_myfault_callback_creation.PNG)
The basic block shows that the driver works exactly how Mark described it in his blogpost, by registering a callback function which will be executed when a Bug Check is triggered. From the blogpost we also know that the color change is achieved by directly modifying the boot video drivers settings, this means it almost definitly needs to use the [out](http://x86.renejeschke.de/html/file_module_x86_id_222.html) instruction.
"The Myfault.sys callback executes just after the blue screen paints and changes the colors to the ones passed to it by Notmyfault by changing the default VGA palette entries used by the Boot Video driver."

Using IDA's search function to find occurances of the string 'out' we find one function which uses the instruction a bunch of times.
![](/content/images/2016/09/PSOD_out_asm_search.PNG)
When we go to the function in graph view we find that its taking two arguments and using them to set three different values on two different ports, here we can assume these RGB values.
![](/content/images/2016/09/psod_myfault_pallete_change_ida.PNG)
Now we just need to know how this actually works...

The best documentation I could find on interacting with the VGA directly was on [osdev.org](http://wiki.osdev.org/VGA_Hardware). The port '0x3C8' is used to select the color index which is being written to and port '0x3C9' is used to select what color the index represents and is set by writing 3 6-bit values to it, representing red, green and blue. In the code above the user supplied values are being shifted about to set these values and the color indexes '4' and '0xF' are the ones being used to set the color of the background and the text.

I took the assembly and simplified it a bit - hardcoding the colors and removing some of the optimisations to make things clearer and ended up with the below as my callback function, the function is defined as described in the [BugCheckDumpIoCallback ](https://msdn.microsoft.com/en-us/library/windows/hardware/ff540677(v=vs.85).aspx) documentation.
<pre>
VOID BugCheckDumpIoCallback(KBUGCHECK_CALLBACK_REASON Reason, struct _KBUGCHECK_REASON_CALLBACK_RECORD *Record, PVOID ReasonSpecificData, ULONG ReasonSpecificDataLength)
{
	UNREFERENCED_PARAMETER(Reason);
	UNREFERENCED_PARAMETER(Record);
	UNREFERENCED_PARAMETER(ReasonSpecificData);
	UNREFERENCED_PARAMETER(ReasonSpecificDataLength);
	__asm {
		mov edx, 3C8h; DAC color index port
		mov al, 4; background color
		out dx, al
		mov edx, 0x3C9; DAC color component port
		mov al, 0xFF; RED
		out dx, al
		mov al, 0x69; GREEN
		out dx, al
		mov al, 0xB4; BLUE
		out dx, al
		dec edx
		mov al, 0Fh;Text color
		out dx, al
		mov edx, 0x3C9
		mov al, 0x00; RED
		out dx, al
		mov al, 0x00; GREEN
		out dx, al
		mov al, 0x00; BLUE
		out dx, al
	}
}
</pre>

Now that we have our callback function we need to register it as a callback the same way Mark's code did. We do this by initiallizing a callback record using [KeInitializeCallbackRecord](https://msdn.microsoft.com/en-us/library/windows/hardware/ff552109(v=vs.85).aspx) and then registering it using [KeRegisterBugCheckReasonCallback](https://msdn.microsoft.com/en-us/library/windows/hardware/ff553110(v=vs.85).aspx). Supplying a KBUGCHECK_CALLBACK_REASON enum value of 1 means that the callback will always be ran when a Bug Check occurs.

<pre>
KeInitializeCallbackRecord(&callbackRec);
status = KeRegisterBugCheckReasonCallback(&callbackRec, (PKBUGCHECK_REASON_CALLBACK_ROUTINE)&BugCheckDumpIoCallback, (KBUGCHECK_CALLBACK_REASON)1, (PUCHAR) "BUGCHECK");
</pre>

Now we just need to add code to trigger a BugCheck - this can be done easily with the [KeBugCheckEx](https://msdn.microsoft.com/en-us/library/windows/hardware/ff551961(v=vs.85).aspx) function.
<pre>
KeBugCheckEx(0x1234, 0, 1, 2, 3);
</pre>

Now if we rebuild and then re-register and start the service, we see this:

![](/content/images/2016/09/psod-3.PNG)

#### Creating IOCTL handlers
Now we have the driver behaviour we want but it's all in the 'DriverEntry' function, so this non-useful driver is currently rather undriver like. 

In Windows the [DeviceIOControl](https://msdn.microsoft.com/en-gb/library/windows/desktop/aa363216(v=vs.85).aspx) function provides a generic interface to drivers, when the function is called the I/O Manager will create an [IRP](https://msdn.microsoft.com/en-us/library/windows/hardware/ff550694(v=vs.85).aspx) (I/O Request Packet) which it delivers to the device driver, the IRP is just a structure which encapsulates the I/O Request and maintains its request status. The IRP is then passed down the Windows driver stack until a driver that can handle it is found.

We start by defining our desired IOCTL codes using the CTL_CODE macro.
<pre>
#define IOCTL_PSOD_CREATE_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_PSOD_BUG_CHECK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
</pre>
Our IOCTLs are for an unknown device type, have function codes of 0x801 and 0x802 - drivers from vendors other than Microsoft start at 0x800, do not support any kind of IO and can be sent from a process with either read or write permissions to the device.

Next lets restart from scratch with the DriverEntry function.

<pre>
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;
	PDEVICE_OBJECT DeviceObject = NULL;

	WDF_DRIVER_CONFIG_INIT(&config, KmdfPSODEvtDeviceAdd);
	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
	return status;
}
</pre>
Now we want our driver to actually have a device associated with it this time, so that userland programmers can acquire a handle to it, we start off by delcaring variables to store the device name. Two versions of the device name are created with different paths, some details on the reasoning for this can be found [here](https://msdn.microsoft.com/en-gb/library/windows/hardware/ff548088(v=vs.85).aspx).
<pre>
UNICODE_STRING DeviceName, Win32Device;
</pre>
Next we initialize the variables with our chosen device name.
<pre>
RtlInitUnicodeString(&DeviceName, L"\\Device\\PSOD");
RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\PSOD");
</pre>
Next we use the [IoCreateDevice](https://msdn.microsoft.com/en-us/library/windows/hardware/ff548397(v=vs.85).aspx) function to create a device object for our driver.
<pre>
status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
</pre>
Now we're going to setup the DriverObjects main function table, I'll explain the functions we put in the table later on when they are defined. We start by setting 'IrpNotImplementedHandler' as the entry for every function in the MajorFunction table which is used to store references to all the IRP handler functions our driver supports. Having a not implemented handler for any functions we don't support is a good practise and avoids causing confusion when we return error codes to requests which should have been passed to another driver.
<pre>
for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
	DriverObject->MajorFunction[i] = IrpNotImplementedHandler;
}
</pre>
Next we create entries for the IRP handlers which we need. [IRP\_MJ\_CREATE](https://msdn.microsoft.com/en-us/library/windows/hardware/ff548630(v=vs.85).aspx) is used when someone requests a handle to our device, for example by using CreateFile and [IRP\_MJ\_CLOSE](https://msdn.microsoft.com/en-us/library/windows/hardware/ff548621(v=vs.85).aspx) when they close the handle. Finally [IRP\_MJ\_DEVICE\_CONTROL](https://msdn.microsoft.com/en-us/library/windows/hardware/ff550744(v=vs.85).aspx) is called when an IOCTL is sent to the driver.
<pre>
DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateHandler;
DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCloseHandler;
DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PSOD_IoControl;
</pre>

Following this we install an Unload Handler, the purpose of this is pretty obvious as it will be called when the driver is unloaded.

<pre>
DriverObject->DriverUnload = IrpUnloadHandler;
</pre>

Next we modify the flags on our device object so that it is no longer marked as initializing and can start recieving IO requests. More details on this are available [here](https://msdn.microsoft.com/en-us/library/windows/hardware/dn614010(v=vs.85).aspx).

<pre>
DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
</pre>

Finally we add the following just before we return from DriverEntry to actually create the symbolic link used to access the device.
<pre>
status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
</pre>

So now that DriverEntry is sorted we need to create the functions we just placed in the devices MajorFunctions table. We start by defining the 'PSOD_IoControl' function which is called everytime the driver is sent an IOCTL. The first thing the function does is call [IoGetCurrentIrpStackLocation](https://msdn.microsoft.com/en-us/library/windows/hardware/ff549174(v=vs.85).aspx) to find the location of the callers I/O stack location which contains any paramters passed with the Irp. If the stack has been correctly retrieved it then enters a switch which calls the relevant handler functions based off the IoControlCode which was sent. Once the correct handler has returned the status is set and so is the number of bytes written to the return buffer if one was provided.

<pre>
NTSTATUS PSOD_IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	
	NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
	unsigned int dwDataWritten = 0;

	PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

	if (pIoStackIrp)
	{
		switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode){
			case IOCTL_PSOD_CREATE_CALLBACK:
				NtStatus = PSOD_HandleIOCTL_CREATE_CALLBACK(Irp, pIoStackIrp, &dwDataWritten);
				break;

			case IOCTL_PSOD_BUG_CHECK:
				NtStatus = PSOD_HandleIOCTL_BUG_CHECK(Irp, pIoStackIrp, &dwDataWritten);
				break;
			default:
				NtStatus = STATUS_INVALID_DEVICE_REQUEST;
				break;
		}
	}

	Irp->IoStatus.Status = NtStatus;
	Irp->IoStatus.Information = dwDataWritten;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return NtStatus;
}
</pre>
The create callback handler registers our bug check callback function and returns success if it was registered and returns 'STATUS_UNSUCCESSFUL' if it fails.
<pre>
NTSTATUS PSOD_HandleIOCTL_CREATE_CALLBACK(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, unsigned int *pdwDataWritten)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(pIoStackIrp);
	UNREFERENCED_PARAMETER(pdwDataWritten);

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KeInitializeCallbackRecord(&callbackRec);
	status = KeRegisterBugCheckReasonCallback(&callbackRec, (PKBUGCHECK_REASON_CALLBACK_ROUTINE)&BugCheckDumpIoCallback, (KBUGCHECK_CALLBACK_REASON)1, (PUCHAR) "BUGCHECK");
	Irp->IoStatus.Information = 0;
	if (status == STATUS_SUCCESS){
		Irp->IoStatus.Status = STATUS_SUCCESS;
	}
	else {
		Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	}
	return status;
}
</pre>
The bug check callback does exactly what we were doing in DriverEntry before and just calls 'KeBugCheckEx' to trigger a bug check.
<pre>
NTSTATUS PSOD_HandleIOCTL_BUG_CHECK(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, unsigned int *pdwDataWritten)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(pIoStackIrp);
	UNREFERENCED_PARAMETER(pdwDataWritten);
	KeBugCheckEx(0x1234, 0, 1, 2, 3);
}
</pre>
The 'IrpCreateHandler' function just always returns 'STATUS_SUCCESS', we aren't keeping track of open handles or restricting them in anyway so there's nothing we need to do here.
<pre>
NTSTATUS IrpCreateHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
</pre>
The 'IrpCloseHandler' function just return 'STATUS_SUCCESS', we aren't keeping track of open handles or anything, so we don't need to do anything.
<pre>
NTSTATUS IrpCloseHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
</pre>
The 'IrpUnloadHandler' function deletes the symbolic link created for the driver and then deletes the device object associated with it.
<pre>
VOID IrpUnloadHandler(IN PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING DosDeviceName = { 0 };
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\PSOD");
	IoDeleteSymbolicLink(&DosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
}
</pre>
Finally the 'IrpNotImplementedHandler' just returns STATUS\_NOT\_SUPPORTED. 
<pre>
NTSTATUS IrpNotImplementedHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_NOT_SUPPORTED;
}
</pre>

With this done it should be possible to rebuild the driver, register it as a service and start it. Nothing should happen until we start sending it IOCTLs. The full code for the driver can be found [here](https://github.com/sam-b/PSOD/blob/master/PSOD/PSOD/Driver.c).

#### Sending IOCTLs

In order to send IOCTLs to our driver once it has started we need two functions, one to get a handle to the driver and another to send the IOCTL. I used the following functions which were taken from this [gist](https://gist.github.com/santa4nt/11068180) and which provide simple python function wrappers around some ctypes magic used to directly call the needed Windows API functions.

<pre>
import ctypes
import ctypes.wintypes as wintypes
from ctypes import windll

# open_divice and send_ioctl taken from https://gist.github.com/santa4nt/11068180
LPDWORD = ctypes.POINTER(wintypes.DWORD)
LPOVERLAPPED = wintypes.LPVOID
LPSECURITY_ATTRIBUTES = wintypes.LPVOID

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000

OPEN_EXISTING = 3

FILE_ATTRIBUTE_NORMAL = 0x00000080

INVALID_HANDLE_VALUE = -1

NULL = 0

def open_device(device_path, access, mode, creation, flags):
	"""See: CreateFile function
	http://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
	"""
	CreateFile_Fn = windll.kernel32.CreateFileW
	CreateFile_Fn.argtypes = [
	wintypes.LPWSTR,                    # _In_          LPCTSTR lpFileName
	wintypes.DWORD,                     # _In_          DWORD dwDesiredAccess
	wintypes.DWORD,                     # _In_          DWORD dwShareMode
	LPSECURITY_ATTRIBUTES,              # _In_opt_      LPSECURITY_ATTRIBUTES lpSecurityAttributes
	wintypes.DWORD,                     # _In_          DWORD dwCreationDisposition
	wintypes.DWORD,                     # _In_          DWORD dwFlagsAndAttributes
	wintypes.HANDLE]                    # _In_opt_      HANDLE hTemplateFile
	CreateFile_Fn.restype = wintypes.HANDLE

	return wintypes.HANDLE(CreateFile_Fn(device_path,
	access,
	mode,
	NULL,
	creation,
	flags,
	NULL))

def send_ioctl(devhandle, ioctl, inbuf, inbufsiz, outbuf, outbufsiz,):
	"""See: DeviceIoControl function
	http://msdn.microsoft.com/en-us/library/aa363216(v=vs.85).aspx
	"""
	DeviceIoControl_Fn = windll.kernel32.DeviceIoControl
	DeviceIoControl_Fn.argtypes = [
	wintypes.HANDLE,                    # _In_          HANDLE hDevice
	wintypes.DWORD,                     # _In_          DWORD dwIoControlCode
	wintypes.LPVOID,                    # _In_opt_      LPVOID lpInBuffer
	wintypes.DWORD,                     # _In_          DWORD nInBufferSize
	wintypes.LPVOID,                    # _Out_opt_     LPVOID lpOutBuffer
	wintypes.DWORD,                     # _In_          DWORD nOutBufferSize
	LPDWORD,                            # _Out_opt_     LPDWORD lpBytesReturned
	LPOVERLAPPED]                       # _Inout_opt_   LPOVERLAPPED lpOverlapped
	DeviceIoControl_Fn.restype = wintypes.BOOL

	# allocate a DWORD, and take its reference
	dwBytesReturned = wintypes.DWORD(0)
	lpBytesReturned = ctypes.byref(dwBytesReturned)

	status = DeviceIoControl_Fn(devhandle,
	ioctl,
	inbuf,
	inbufsiz,
	outbuf,
	outbufsiz,
	lpBytesReturned,
	None)

	return status, dwBytesReturned
</pre>

Next we need to get the IOCTL codes actual values so we can send them, these were calculated using the [translate.py](https://github.com/sam-b/win-driver-tools/blob/master/translate.py) script I have on Github which maps the constant names to thier values and then uses them to calculate the IOCTL code.

<pre>
if __name__ == "__main__":
	#define IOCTL_PSOD_CREATE_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
	create_callback_ioctl = 0x22e007
	#define IOCTL_PSOD_BUG_CHECK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
	bug_check_ioctl = 0x22e00b
</pre>

Sending the IOCTLs is easy enough - first we get a handle to the device using standard permissions and the path we chose earlier, then we send the create\_callback\_ioctl followed by the bug\_check\_ioctl. We aren't transferring any data so the all the input and output buffers can just be None.
<pre>
	device_handle = open_device("\\\\.\\PSOD", GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL)
	send_ioctl(device_handle, create_callback_ioctl, None, 0, None, 0)
	send_ioctl(device_handle, bug_check_ioctl, None, 0, None, 0)
</pre>

When we run this from the command line, we see the pink and black screen of death appear which means...

![](/content/images/2016/09/lol.jpg)