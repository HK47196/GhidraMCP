#include <cstdio>
#include <cstring>

// ==================== Basic Classes ====================

// Simple class without virtual functions
class SimpleClass {
public:
    int value;

    SimpleClass() : value(0) {}
    SimpleClass(int v) : value(v) {}

    int getValue() const { return value; }
    void setValue(int v) { value = v; }
    int doubleValue() const { return value * 2; }
};

// ==================== Inheritance Hierarchy ====================

// Base class with virtual functions (will have vtable)
class Animal {
protected:
    int age;
    char name[32];

public:
    Animal() : age(0) {
        strcpy(name, "Unknown");
    }

    Animal(const char* n, int a) : age(a) {
        strncpy(name, n, 31);
        name[31] = '\0';
    }

    virtual ~Animal() {}

    virtual void speak() const {
        printf("Animal says nothing\n");
    }

    virtual int getLegs() const {
        return 0;
    }

    const char* getName() const { return name; }
    int getAge() const { return age; }

    // Non-virtual method
    void birthday() {
        age++;
    }
};

// Derived class - Dog
class Dog : public Animal {
private:
    char breed[32];

public:
    Dog() : Animal() {
        strcpy(breed, "Unknown");
    }

    Dog(const char* n, int a, const char* b) : Animal(n, a) {
        strncpy(breed, b, 31);
        breed[31] = '\0';
    }

    virtual ~Dog() {}

    void speak() const override {
        printf("%s says: Woof!\n", name);
    }

    int getLegs() const override {
        return 4;
    }

    const char* getBreed() const { return breed; }

    void fetch() {
        printf("%s is fetching!\n", name);
    }
};

// Derived class - Cat
class Cat : public Animal {
private:
    bool isIndoor;

public:
    Cat() : Animal(), isIndoor(true) {}

    Cat(const char* n, int a, bool indoor) : Animal(n, a), isIndoor(indoor) {}

    virtual ~Cat() {}

    void speak() const override {
        printf("%s says: Meow!\n", name);
    }

    int getLegs() const override {
        return 4;
    }

    bool getIndoor() const { return isIndoor; }

    void purr() {
        printf("%s is purring\n", name);
    }
};

// Derived class - Bird
class Bird : public Animal {
private:
    double wingspan;

public:
    Bird() : Animal(), wingspan(0.0) {}

    Bird(const char* n, int a, double ws) : Animal(n, a), wingspan(ws) {}

    virtual ~Bird() {}

    void speak() const override {
        printf("%s says: Tweet!\n", name);
    }

    int getLegs() const override {
        return 2;
    }

    double getWingspan() const { return wingspan; }

    virtual void fly() {
        printf("%s is flying with wingspan %.1f\n", name, wingspan);
    }
};

// ==================== Multiple Inheritance ====================

class Swimmer {
public:
    virtual void swim() {
        printf("Swimming...\n");
    }
    virtual ~Swimmer() {}
};

class Flyer {
public:
    virtual void fly() {
        printf("Flying...\n");
    }
    virtual ~Flyer() {}
};

// Duck inherits from Bird (which has Animal) and Swimmer
class Duck : public Bird, public Swimmer {
public:
    Duck() : Bird() {}
    Duck(const char* n, int a, double ws) : Bird(n, a, ws) {}

    virtual ~Duck() {}

    void speak() const override {
        printf("%s says: Quack!\n", getName());
    }

    void swim() override {
        printf("%s the duck is swimming\n", getName());
    }

    void fly() override {
        printf("%s the duck is flying\n", getName());
    }
};

// ==================== Abstract Class ====================

class Shape {
public:
    virtual ~Shape() {}
    virtual double area() const = 0;
    virtual double perimeter() const = 0;
    virtual const char* shapeName() const = 0;
};

class Rectangle : public Shape {
private:
    double width;
    double height;

public:
    Rectangle(double w, double h) : width(w), height(h) {}

    double area() const override {
        return width * height;
    }

    double perimeter() const override {
        return 2 * (width + height);
    }

    const char* shapeName() const override {
        return "Rectangle";
    }

    double getWidth() const { return width; }
    double getHeight() const { return height; }
};

class Circle : public Shape {
private:
    double radius;

public:
    Circle(double r) : radius(r) {}

    double area() const override {
        return 3.14159 * radius * radius;
    }

    double perimeter() const override {
        return 2 * 3.14159 * radius;
    }

    const char* shapeName() const override {
        return "Circle";
    }

    double getRadius() const { return radius; }
};

// ==================== Namespace ====================

namespace MathUtils {
    int add(int a, int b) {
        return a + b;
    }

    int multiply(int a, int b) {
        return a * b;
    }

    namespace Advanced {
        int power(int base, int exp) {
            int result = 1;
            for (int i = 0; i < exp; i++) {
                result *= base;
            }
            return result;
        }
    }
}

// ==================== Static Members ====================

class Counter {
private:
    static int count;
    int id;

public:
    Counter() : id(++count) {}

    static int getCount() { return count; }
    int getId() const { return id; }

    static void reset() { count = 0; }
};

int Counter::count = 0;

// ==================== Operator Overloading ====================

class Point {
public:
    int x;
    int y;

    Point() : x(0), y(0) {}
    Point(int px, int py) : x(px), y(py) {}

    Point operator+(const Point& other) const {
        return Point(x + other.x, y + other.y);
    }

    Point operator-(const Point& other) const {
        return Point(x - other.x, y - other.y);
    }

    bool operator==(const Point& other) const {
        return x == other.x && y == other.y;
    }

    Point& operator+=(const Point& other) {
        x += other.x;
        y += other.y;
        return *this;
    }
};

// ==================== Function Overloading ====================

int process(int x) {
    return x * 2;
}

int process(int x, int y) {
    return x + y;
}

double process(double x) {
    return x * 2.5;
}

const char* process(const char* s) {
    return s;
}

// ==================== Helper Functions ====================

void testPolymorphism() {
    Animal* animals[4];
    animals[0] = new Dog("Rex", 5, "German Shepherd");
    animals[1] = new Cat("Whiskers", 3, true);
    animals[2] = new Bird("Tweety", 1, 0.3);
    animals[3] = new Duck("Donald", 2, 0.5);

    for (int i = 0; i < 4; i++) {
        printf("Animal: %s, Age: %d, Legs: %d\n",
               animals[i]->getName(),
               animals[i]->getAge(),
               animals[i]->getLegs());
        animals[i]->speak();
        delete animals[i];
    }
}

void testShapes() {
    Shape* shapes[2];
    shapes[0] = new Rectangle(5.0, 3.0);
    shapes[1] = new Circle(2.0);

    for (int i = 0; i < 2; i++) {
        printf("%s: area=%.2f, perimeter=%.2f\n",
               shapes[i]->shapeName(),
               shapes[i]->area(),
               shapes[i]->perimeter());
        delete shapes[i];
    }
}

void testNamespaces() {
    int sum = MathUtils::add(10, 20);
    int product = MathUtils::multiply(5, 6);
    int power = MathUtils::Advanced::power(2, 8);

    printf("Sum: %d, Product: %d, Power: %d\n", sum, product, power);
}

void testOperators() {
    Point p1(3, 4);
    Point p2(1, 2);

    Point p3 = p1 + p2;
    Point p4 = p1 - p2;

    printf("p1+p2 = (%d, %d)\n", p3.x, p3.y);
    printf("p1-p2 = (%d, %d)\n", p4.x, p4.y);
    printf("p1==p2: %s\n", (p1 == p2) ? "true" : "false");
}

void testOverloading() {
    int r1 = process(5);
    int r2 = process(3, 7);
    double r3 = process(2.5);
    const char* r4 = process("hello");

    printf("process(5)=%d, process(3,7)=%d, process(2.5)=%.1f, process(hello)=%s\n",
           r1, r2, r3, r4);
}

// ==================== Main ====================

int main(int argc, char** argv) {
    printf("=== C++ Test Binary ===\n\n");

    // Test simple class
    SimpleClass sc(42);
    printf("SimpleClass value: %d, doubled: %d\n\n", sc.getValue(), sc.doubleValue());

    // Test polymorphism
    printf("--- Polymorphism Test ---\n");
    testPolymorphism();
    printf("\n");

    // Test abstract class / shapes
    printf("--- Shapes Test ---\n");
    testShapes();
    printf("\n");

    // Test namespaces
    printf("--- Namespace Test ---\n");
    testNamespaces();
    printf("\n");

    // Test static members
    printf("--- Static Members Test ---\n");
    Counter c1, c2, c3;
    printf("Counter count: %d, IDs: %d, %d, %d\n\n",
           Counter::getCount(), c1.getId(), c2.getId(), c3.getId());

    // Test operators
    printf("--- Operator Test ---\n");
    testOperators();
    printf("\n");

    // Test overloading
    printf("--- Overloading Test ---\n");
    testOverloading();
    printf("\n");

    printf("=== Tests Complete ===\n");
    return 0;
}
