
file (GLOB ATTR_SRCS "executor/*.cpp")
list (FILTER ATTR_SRCS EXCLUDE REGEX "_test.cpp")

list (APPEND ATTR_SRCS expression_visitor.cpp attribute.cpp attr_type_schema.cpp)

add_library (attr OBJECT ${ATTR_SRCS})
target_link_libraries (attr PUBLIC coverage_config)

add_dependencies (attr spdlog fmt::fmt antlr4)
