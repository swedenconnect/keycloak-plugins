/*
 * Copyright 2025 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package se.swedenconnect.test;


import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

public class MappingTester {

  public static Stream<Arguments> mappingArguments() {
    return Stream.of(
        Arguments.of(Map.of("urn:oid:1.2.752.29.4.13", "YYYYMMDDXXXX")),
        Arguments.of(Map.of("urn:oid:2.5.4.42", "FirstName")),
        Arguments.of(Map.of("urn:oid:2.5.4.4", "LastName"))
    );
  }

  @ParameterizedTest
  @MethodSource("mappingArguments")
  void testSamlAssertionParameterMapping(Map<String, String> arguments) {
    final TestContext context = new TestContext(arguments);
    final MappingTestResult result = new MapperWrapper().getResult(context);
    result.printReport();
  }

}
