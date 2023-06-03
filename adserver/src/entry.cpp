#include <iostream>
#include <cstdint>
#include <windows.h>
#include "safe_call.hpp"
#include "image.hpp"

void hey( ) {

}

int main( ) {
    LoadLibrary("adclient.dll");

    printf("heey\n");
    //hey();

    return 1;
}