package it.agid.spid.saml.core.utils;
import java.util.function.Consumer;

/**
 * A Utility which provides a way to throw checked exceptions from the lambda expressions.
 */
public class LambdaExceptionUtil {

    /**
     * Represents a {@code Consumer} interface which can throw exceptions.
     *
     * @param <T> The type of the input to the operation.
     * @param <E> The type of Exception.
     */
    @FunctionalInterface
    public interface ConsumerWithExceptions<T, E extends Exception> {

        void accept(T t) throws E;
    }

    /**
     * This method allows a Consumer which throws exceptions to be used in places which expects a Consumer.
     *
     * @param consumer Instances of the {@code ConsumerWithExceptions} functional interface.
     * @param <T>      The type of the input to the function.
     * @param <E>      The type of Exception.
     * @return An instance of the {@code Consumer}
     */
    public static <T, E extends Exception> Consumer<T> rethrowConsumer(ConsumerWithExceptions<T, E> consumer) {

        return t -> {
            try {
                consumer.accept(t);
            } catch (Exception exception) {
                throwAsUnchecked(exception);
            }
        };
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {

        throw (E) exception;
    }
}
