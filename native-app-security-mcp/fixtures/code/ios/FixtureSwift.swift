@inline(never)
public func fixtureSwiftHelper(_ value: Int32) -> Int32 {
    return value &+ 7
}

@_cdecl("fixture_swift_entry")
public func fixtureSwiftEntry(_ value: Int32) -> Int32 {
    return fixtureSwiftHelper(value)
}
