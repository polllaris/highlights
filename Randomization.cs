using System;
using System.Collections.Generic;

public class RandomUtils {

	static Random rand = new Random();

	public static bool chancedBoolean(double chance) {

		// return a boolean and have it based on the given chance
		// i.e a chance of 25.00 will give it a 25.00% chance of returning
		// true -> Generates a random number between 0 and 100 and if that
		// number is less than the given chance it will return true, else false.

		return (rand.NextDouble() + rand.Next(1, 100)) <= chance;
	}
/*
	public static List<(T1, T2)> chancedSelection<T1, T2>(uint amount, List<(T1, T2)> list) {


		List<T2> selection = new List<T2>();
		while (list.Count < selection.Count) {
			foreach(var element in list) {
				var (chance, item) = element;
				if (chancedBoolean((double)chance)) {
					selection.Add(item);
				}
			}
		}

		return selection;

	}
*/
	public static List<T> chancedSelection<T>(uint amount, List<(double, T)> selectable) {

		List<T> selected = new List<T>();
		while(selectable.Count > selected.Count) {
			foreach(var e in selectable) {
				var (chance, element) = e;
				if(chancedBoolean(chance)) {
					selected.Add(element);
					if(selected.Count > selectable.Count) break;
				}
			}
		}

		return selected;

	}
}

public class Randomization {

	public static void Main() {

		List<(int, string)> tempList = new List<(int, string)>();


		//RandomUtils.chancedSelection(5, tempList);



	}
}
