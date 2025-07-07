#include "Registry.h"

Registry::Registry(HKEY root, const std::wstring& subkey, REGSAM access) {
    open(root, subkey, access);
}

Registry::~Registry() {
    close();
}

void Registry::close() noexcept {
    if (m_key) {
        RegCloseKey(m_key);
        m_key = nullptr;
    }
}

bool Registry::open(HKEY root, const std::wstring& subkey, REGSAM access) {
    close();
    LSTATUS status = RegOpenKeyExW(root, subkey.c_str(), 0, access, &m_key);
    m_lastErr = toErrorCode(status);

    return status == ERROR_SUCCESS;
}

bool Registry::create(HKEY root, const std::wstring& subkey, REGSAM access) {
    close();
    DWORD disp = { };
    LONG status = RegCreateKeyExW(
        root,
        subkey.c_str(),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        access,
        nullptr,
        &m_key,
        &disp
    );
    m_lastErr = toErrorCode(status);

    return status == ERROR_SUCCESS;
}
