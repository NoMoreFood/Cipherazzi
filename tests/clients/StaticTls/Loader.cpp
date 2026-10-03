#include <windows.h>

int main(int argc, char** argv)
{
    if (argc != 6) return 1;

    // Exercise symbol lookup after a module loads, unloads, and loads again in the same application.
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        const auto library = LoadLibraryA(argv[1]);
        if (!library) return 1;
        const auto run = reinterpret_cast<int (*)(int, char**)>(GetProcAddress(library, "RunTlsClient"));
        const auto result = run ? run(argc - 1, argv + 1) : 1;
        FreeLibrary(library);
        if (result) return result;
    }
    return 0;
}
