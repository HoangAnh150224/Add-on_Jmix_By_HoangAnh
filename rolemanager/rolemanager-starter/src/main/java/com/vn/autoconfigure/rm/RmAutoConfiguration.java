package com.vn.autoconfigure.rm;

import com.vn.rm.RmConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

@AutoConfiguration
@Import({RmConfiguration.class})
public class RmAutoConfiguration {
}

