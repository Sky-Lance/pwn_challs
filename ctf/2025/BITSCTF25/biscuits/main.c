#include <stdio.h>
#include <stdlib.h>
#include <time.h>

const char *cookies[] = {
    "Chocolate Chip", "Sugar Cookie", "Oatmeal Raisin", "Peanut Butter", "Snickerdoodle",
    "Shortbread", "Gingerbread", "Macaron", "Macaroon", "Biscotti",
    "Butter Cookie", "White Chocolate Macadamia Nut", "Double Chocolate Chip", "M&M Cookie", "Lemon Drop Cookie",
    "Coconut Cookie", "Almond Cookie", "Thumbprint Cookie", "Fortune Cookie", "Black and White Cookie",
    "Molasses Cookie", "Pumpkin Cookie", "Maple Cookie", "Espresso Cookie", "Red Velvet Cookie",
    "Funfetti Cookie", "S'mores Cookie", "Rocky Road Cookie", "Caramel Apple Cookie", "Banana Bread Cookie",
    "Zucchini Cookie", "Matcha Green Tea Cookie", "Chai Spice Cookie", "Lavender Shortbread", "Earl Grey Tea Cookie",
    "Pistachio Cookie", "Hazelnut Cookie", "Pecan Sandies", "Linzer Cookie", "Spritz Cookie",
    "Russian Tea Cake", "Anzac Biscuit", "Florentine Cookie", "Stroopwafel", "Alfajores",
    "Polvor", "Springerle", "Pfeffern", "Speculoos", "Kolaczki",
    "Rugelach", "Hamantaschen", "Mandelbrot", "Koulourakia", "Melomakarona",
    "Kourabiedes", "Pizzelle", "Amaretti", "Cantucci", "Savoiardi (Ladyfingers)",
    "Madeleine", "Palmier", "Tuile", "Langue de Chat", "Viennese Whirls",
    "Empire Biscuit", "Jammie Dodger", "Digestive Biscuit", "Hobnob", "Garibaldi Biscuit",
    "Bourbon Biscuit", "Custard Cream", "Ginger Nut", "Nice Biscuit", "Shortcake",
    "Jam Thumbprint", "Coconut Macaroon", "Chocolate Crinkle", "Pepparkakor", "Sandbakelse",
    "Krumkake", "Rosette Cookie", "Pinwheel Cookie", "Checkerboard Cookie", "Rainbow Cookie",
    "Mexican Wedding Cookie", "Snowball Cookie", "Cranberry Orange Cookie", "Pumpkin Spice Cookie", "Cinnamon Roll Cookie",
    "Chocolate Hazelnut Cookie", "Salted Caramel Cookie", "Toffee Crunch Cookie", "Brownie Cookie", "Cheesecake Cookie",
    "Key Lime Cookie", "Blueberry Lemon Cookie", "Raspberry Almond Cookie", "Strawberry Shortcake Cookie", "Neapolitan Cookie"
};

int main() {
    time_t current_time;
    current_time = time(NULL);
    srand(current_time);

    for (int i = 0; i < 100; i++) {
        int cookie_index = rand() % 100;
        printf("%s\n", cookies[cookie_index]); 
    }

    return 0;
}