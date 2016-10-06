if(TARGET_LIKE_LINUX)
include("../includes.txt")
add_executable(m2mconnectionhandlerpimpl_classic
        "../../../../source/m2mconnectionhandlerpimpl.cpp"
       	"main.cpp"
        "m2mconnectionhandlerpimpl_classic_test.cpp"
        "test_m2mconnectionhandlerpimpl_classic.cpp"
       "../stub/common_stub.cpp"
       "../stub/nsdlaccesshelper_stub.cpp"
       "../stub/m2msecurity_stub.cpp"
       "../stub/m2mconnectionsecurity_stub.cpp"
       "../stub/m2mstring_stub.cpp"
       "../stub/m2mobject_stub.cpp"
       "../stub/m2mresource_stub.cpp"
       "../stub/m2mresourceinstance_stub.cpp"
       "../stub/m2mbase_stub.cpp"
       "../stub/m2mconnectionsecurity_stub.cpp"
       "../stub/pal_network_stub.cpp"
)
target_link_libraries(m2mconnectionhandlerpimpl_classic
    CppUTest
    CppUTestExt
)
set_target_properties(m2mconnectionhandlerpimpl_classic
PROPERTIES COMPILE_FLAGS "${UTEST_COMPILE_FLAGS}"
           LINK_FLAGS "${UTEST_LINK_FLAGS}")

set(binary "m2mconnectionhandlerpimpl_classic -ojunit")
add_test(m2mconnectionhandlerpimpl_classic ${binary})

endif()
