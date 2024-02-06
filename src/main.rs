use roxmltree::Document;
use std::error::Error;
use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::*;
use winapi::um::winnt::{HANDLE, LPWSTR};
use winapi::um::wlanapi::*;
use std::ptr;
use std::collections::HashMap;

fn main() {
    unsafe {
        let client_handle = open_wlan_handle().expect("Failed to open WLAN handle");
        let mut wifi_pass = HashMap::new(); // We prepare the map that will contain the wifi names and passwords
        enumerate_wlan_interfaces(client_handle, &mut wifi_pass);
        for (wifi, pass) in wifi_pass {
            println!("Wifi : {} | Password : {}", wifi, pass);
        }
        WlanCloseHandle(client_handle, ptr::null_mut());
    }
}

fn open_wlan_handle() -> Result<HANDLE, DWORD> {
    unsafe {
        // Hold the handle to the WLAN client, initialized to a null pointer
        let mut client_handle: HANDLE = ptr::null_mut();
        // Hold the negotiated version of the WLAN API. Initialized to 0
        let mut negotiated_version: DWORD = 0;
        // Specify the client version of the WLAN API we want to use
        let dw_client_version: DWORD = 2;
        // Opening the handle and storing the handle into WLAN client_handle
        let result = WlanOpenHandle(
            dw_client_version,
            ptr::null_mut(),
            &mut negotiated_version,
            &mut client_handle,
        );
        if result == 0 { // We receive the handle
            Ok(client_handle)
        } else {
            Err(result)
        }
    }
}

// Defines a function to enumerate WLAN interfaces and list WLAN profiles associated with each interface
fn enumerate_wlan_interfaces(client_handle: HANDLE, wifi_pass: &mut HashMap<String, String>) {
    unsafe {
        // Initialize a pointer for storing the list of WLAN interfaces, initially set to null pointer
        let mut if_list: PWLAN_INTERFACE_INFO_LIST = ptr::null_mut();
        // Calls the Windows API function to enumerate all WLAN interfaces available on the system
        let enum_result = WlanEnumInterfaces(
            client_handle, // The handle that we opened
            ptr::null_mut(),
            &mut if_list,
        );
        // Check if the function call was successful (returns 0 on success)
        if enum_result == 0 {
            let if_list_ref: &WLAN_INTERFACE_INFO_LIST = &*if_list;
            // Iterates over each interface in the list based on the number of items
            for i in 0..if_list_ref.dwNumberOfItems {
                // Calculates the address of the current interface info in the array and gets a reference to it
                let interface_info = &(*if_list_ref.InterfaceInfo.as_ptr().add(i as usize));
                list_wlan_profiles(wifi_pass, client_handle, interface_info);
            }
            WlanFreeMemory(if_list as *mut _);
        } else {
            eprintln!("WlanEnumInterfaces failed with error: {}", enum_result);
        }
    }
}

// Defines a function to list WLAN profiles for an interface
fn list_wlan_profiles(wifi_pass: &mut HashMap<String, String>, client_handle: HANDLE, interface_info: &WLAN_INTERFACE_INFO) {
    unsafe {
        // Initialize a pointer for storing the list of WLAN profiles, initially set to null pointer
        let mut profile_list: PWLAN_PROFILE_INFO_LIST = ptr::null_mut();
        // Calls the Windows API function to enumerate all WLAN profiles related to the interface
        let profile_result = WlanGetProfileList(
            client_handle,
            &interface_info.InterfaceGuid, // The GUID of the interface
            ptr::null_mut(),
            &mut profile_list,
        );
        if profile_result == 0 {
            let profile_list_ref: &WLAN_PROFILE_INFO_LIST = &*profile_list;
            // Iterates over each profile in the list based on the number of items
            for j in 0..profile_list_ref.dwNumberOfItems {
                // Calculates the address of the current profile info in the array and gets a reference to it
                let profile_info = &(*profile_list_ref.ProfileInfo.as_ptr().add(j as usize));
                // Call to the final function
                get_plaintext_passwords(wifi_pass, client_handle, &interface_info.InterfaceGuid, profile_info);
            }
            WlanFreeMemory(profile_list as *mut _);
        } else {
            eprintln!("WlanGetProfileList failed with error: {}", profile_result);
        }
    }
}

// Defines a function to retrieve plaintext passwords from WLAN profiles and store them in a HashMap
fn get_plaintext_passwords(wifi_pass: &mut HashMap<String, String>, client_handle: HANDLE, interface_guid: &GUID, profile_info: &WLAN_PROFILE_INFO) {
    unsafe {
        // Initialize flags to indicate that the plaintext key should be included in the profile returned by WlanGetProfile
        let mut flags: DWORD = WLAN_PROFILE_GET_PLAINTEXT_KEY;
        // Initialize a pointer for storing the XML profile data, initially set to null
        let mut profile_xml: LPWSTR = ptr::null_mut();
        // Calls the WlanGetProfile function to retrieve the profile XML for the specified interface and profile name
        let profile_result = WlanGetProfile(
            client_handle,
            interface_guid,
            profile_info.strProfileName.as_ptr(),
            ptr::null_mut(),
            &mut profile_xml,
            &mut flags,
            ptr::null_mut(),
        );

        if profile_result == 0 {
            // We use a function to convert the LPWSTR profile XML data to string
            let profile_xml_str = lpwstr_to_string(profile_xml);
            // Attempts to parse the XML string to extract the network name and key material (password)
            match sort_xml(profile_xml_str) {
                Ok((name, key_material)) => {
                    // If the key material exists, insert the network name and password into the HashMap, the HashMap will be printed in main function
                    // The open wifi without password won't be printed
                    if let Some(km) = key_material {
                        wifi_pass.insert(name, km);
                    }
                },
                Err(e) => eprintln!("[x] Failed extracting the XML data: {}", e),
            }

            WlanFreeMemory(profile_xml as *mut _);
        } else {
            eprintln!("[x] WlanGetProfile failed with error: {}", profile_result);
        }
    }
}

fn sort_xml(xml_data: String) -> Result<(String, Option<String>), Box<dyn Error>> {
    let doc = Document::parse(&xml_data)?;

    let profile_name_node = doc.descendants().find(|n| n.has_tag_name("name"));
    let key_material_node = doc.descendants().find(|n| n.has_tag_name("keyMaterial"));

    let name = profile_name_node
        .and_then(|n| n.text())
        .ok_or("Profile name not found")?
        .to_string();

    let key_material = key_material_node.and_then(|n| n.text()).map(String::from);

    Ok((name, key_material))
}

fn lpwstr_to_string(ptr: LPWSTR) -> String {
    unsafe {
        let mut len = 0;
        while *ptr.offset(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len as usize);
        String::from_utf16_lossy(slice)
    }
}
