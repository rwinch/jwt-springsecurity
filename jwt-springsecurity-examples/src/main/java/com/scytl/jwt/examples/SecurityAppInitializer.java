/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.scytl.jwt.examples;

import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

/**
 * <p>
 * This registers the Spring Bean named springSecurityFilterChain as a Filter to all URLs.
 * </p>
 *
 * <p>In a Spring Boot application this is not necessary because Spring Boot is smart enough to automatically register
 * any Spring Beans that implement Filter with the Servlet environment.</p>
 *
 * <p>
 * In a web.xml environment this
 * would be done using something similar to this:
 * </p>
 *
 * <code>
 * &lt;filter&gt;
 *   &lt;filter-name&gt;springSecurityFilterChain&lt;/filter-name&gt;
 *   &lt;filter-class&gt;org.springframework.web.filter.DelegatingFilterProxy&lt;/filter-class&gt;
 * &lt;/filter&gt;
 *
 * &lt;filter-mapping&gt;
 *   &lt;filter-name&gt;springSecurityFilterChain&lt;/filter-name&gt;
 *   &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
 * &lt;/filter-mapping&gt;
 * </code>
 *
 * <p>
 * Additional information can be found within the Spring Security
 * <a href="http://docs.spring.io/spring-security/site/docs/3.2.x/guides/hellomvc.html#registering-spring-security-with-the-war">guides</a>
 * and
 * <a href="http://docs.spring.io/spring-security/site/docs/3.2.x/reference/htmlsingle/#abstractsecuritywebapplicationinitializer-with-spring-mvc">documentation</a>
 * </p>
 * 
 * @author Rob Winch
 */
public class SecurityAppInitializer extends AbstractSecurityWebApplicationInitializer {
}
