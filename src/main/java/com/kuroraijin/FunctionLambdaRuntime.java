package com.kuroraijin;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import io.micronaut.function.aws.runtime.AbstractMicronautLambdaRuntime;

import java.net.MalformedURLException;
import java.util.Map;

public class FunctionLambdaRuntime extends AbstractMicronautLambdaRuntime<
        Map<String, Object>, Map<String, Object>,
        Map<String, Object>, Map<String, Object>>
{
    public static void main(String[] args) {
        try {
            new FunctionLambdaRuntime().run(args);

        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected RequestHandler<Map<String, Object>, Map<String, Object>> createRequestHandler(String... args) {
        return new CoreAuthorizerHandler();
    }
}
