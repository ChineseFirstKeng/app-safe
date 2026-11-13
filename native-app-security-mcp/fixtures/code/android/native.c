__attribute__((noinline)) const char *fixture_elf_helper(void) {
    return "fixture-elf-literal";
}
__attribute__((noinline)) const char *fixture_elf_entry(void) {
    return fixture_elf_helper();
}
